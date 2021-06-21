// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/jump_label.h>
#include <linux/trace_events.h>
#include <linux/pagemap.h>

#include <asm/kvm_boot.h>
#include <asm/virtext.h>

#include "common.h"
#include "cpuid.h"
#include "ept.h"
#include "lapic.h"
#include "tdx.h"
#include "tdx_errno.h"
#include "tdx_ops.h"

#include <trace/events/kvm.h>
#include "trace.h"

#ifdef CONFIG_KVM_INTEL_TDX

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

#include "seam.c"

bool __read_mostly emulate_seam = 1;
module_param(emulate_seam, bool, 0444);

static char *seam_module;
module_param(seam_module, charp, 0444);

/* Capabilities of KVM + TDX-SEAM. */
struct tdx_capabilities tdx_capabilities;

/*
 * A per-CPU list of TD vCPUs associated with a given CPU.  Used when a CPU
 * is brought down to invoke TDFLUSHVP on the approapriate TD vCPUS.
 */
static DEFINE_PER_CPU(struct list_head, associated_tdvcpus);

/*
 * A handful of places call into KVM and need to use the vCPU seen by KVM.
 */
static inline struct kvm_vcpu *to_kvm_vcpu(struct kvm_vcpu *vcpu)
{
	if (emulate_seam)
		return (void *)to_tdx(vcpu)->tdvpr.va;
	return vcpu;
}

static __always_inline unsigned long tdexit_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rcx_read(vcpu);
}
static __always_inline unsigned long tdexit_ext_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rdx_read(vcpu);
}
static __always_inline unsigned long tdexit_gpa(struct kvm_vcpu *vcpu)
{
	return kvm_r8_read(vcpu);
}
static __always_inline unsigned long tdexit_intr_info(struct kvm_vcpu *vcpu)
{
	return kvm_r9_read(vcpu);
}

#define BUILD_TDVMCALL_ACCESSORS(param, gpr)				    \
static __always_inline							    \
unsigned long tdvmcall_##param##_read(struct kvm_vcpu *vcpu)		    \
{									    \
	return kvm_##gpr##_read(vcpu);					    \
}									    \
static __always_inline void tdvmcall_##param##_write(struct kvm_vcpu *vcpu, \
						     unsigned long val)	    \
{									    \
	kvm_##gpr##_write(vcpu, val);					    \
}
BUILD_TDVMCALL_ACCESSORS(p1, r12);
BUILD_TDVMCALL_ACCESSORS(p2, r13);
BUILD_TDVMCALL_ACCESSORS(p3, r14);
BUILD_TDVMCALL_ACCESSORS(p4, r15);

static __always_inline unsigned long tdvmcall_exit_type(struct kvm_vcpu *vcpu)
{
	return kvm_r10_read(vcpu);
}
static __always_inline unsigned long tdvmcall_exit_reason(struct kvm_vcpu *vcpu)
{
	return kvm_r11_read(vcpu);
}
static __always_inline void tdvmcall_set_return_code(struct kvm_vcpu *vcpu,
						     long val)
{
	kvm_r10_write(vcpu, val);
}
static __always_inline void tdvmcall_set_return_val(struct kvm_vcpu *vcpu,
						    unsigned long val)
{
	kvm_r11_write(vcpu, val);
}

static inline bool is_td_vcpu_initialized(struct vcpu_tdx *tdx)
{
	return tdx->tdvpr.added;
}

static inline bool is_td_initialized(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr.added;
}

static inline bool is_td_in_teardown(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->hkid < 0;
}

static int tdx_alloc_td_page(struct tdx_td_page *page)
{
	page->va = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!page->va)
		return -ENOMEM;

	page->pa = __pa(page->va);
	return 0;
}

static void tdx_free_td_page(struct tdx_td_page *page)
{
	/*
	 * Don't free a page that has been added but not reclaimed, doing so
	 * will lead to a #MC due to accessing the page with the wrong key.
	 */
	if (WARN_ON_ONCE(page->added))
		return;

	free_page(page->va);
}

static void tdx_add_td_page(struct tdx_td_page *page)
{
	WARN_ON_ONCE(page->added);
	page->added = true;
}

static void tdx_reclaim_td_page(struct tdx_td_page *page)
{
	struct tdx_ex_ret ex_ret;
	u64 err;

	if (page->added) {
		err= tdreclaimpage(page->pa, &ex_ret);
		if (TDX_ERR(err, TDRECLAIMPAGE))
			return;

		err = tdwbinvdpage(page->pa);
		if (TDX_ERR(err, TDWBINVDPAGE))
			return;

		page->added = false;
	}

	tdx_free_td_page(page);
}

static inline void tdx_disassociate_vp(struct kvm_vcpu *vcpu)
{
	list_del(&to_tdx(vcpu)->cpu_list);

	/*
	 * Ensure tdx->cpu_list is updated is before setting vcpu->cpu to -1,
	 * otherwise, a different CPU can see vcpu->cpu = -1 and add the vCPU
	 * to its list before its deleted from this CPUs list.
	 */
	smp_wmb();

	vcpu->cpu = -1;
}

static void tdx_flush_vp(void *arg)
{
	struct kvm_vcpu *vcpu = arg;
	u64 err;

	/* Task migration can race with CPU offlining. */
	if (vcpu->cpu != raw_smp_processor_id())
		return;

	err = tdflushvp(to_tdx(vcpu)->tdvpr.pa);
	if (unlikely(err && err != TDX_VCPU_NOT_ASSOCIATED))
		TDX_ERR(err, TDFLUSHVP);

	tdx_disassociate_vp(vcpu);
}

static void tdx_flush_vp_on_cpu(struct kvm_vcpu *vcpu)
{
	if (vcpu->cpu == -1)
		return;

	/*
	 * No need to do TDFLUSHVP if the vCPU hasn't been initialized.  The
	 * list tracking still needs to be updated so that it's correct if/when
	 * the vCPU does get initialized.
	 */
	if (is_td_vcpu_initialized(to_tdx(vcpu)))
		smp_call_function_single(vcpu->cpu, tdx_flush_vp, vcpu, 1);
	else
		tdx_disassociate_vp(vcpu);
}

static int tdx_vm_init(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int i;

	kvm->arch.shadow_mmio_value = 0;

	kvm_tdx->tdr.pa = INVALID_PAGE;
	for (i = 0; i < tdx_capabilities.tdcs_nr_pages; i++)
		kvm_tdx->tdcs[i].pa = INVALID_PAGE;

	if (emulate_seam)
		return seam_tdcreate(kvm);

	kvm_apicv_init(kvm, true);

	/*
	 * TODO:
	 * SEAMCALL(TDCREATE)
	 */

	/*
	 * Note, cannot invoke TDINIT here.  TDINIT needs to come after all
	 * vCPUs have been created and all pages have been added to the TD.
	 */
	return 0;
}

static void tdx_do_tdwbcache(void *data)
{
	u64 err = 0;

	do {
		err = tdwbcache(!!err);
	} while (err == TDX_INTERRUPTED_RESUMABLE);

	if (err && cmpxchg64((u64 *)data, 0, err) == 0)
		TDX_ERR(err, TDWBCACHE);
}

static void tdx_vm_teardown(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_vcpu *vcpu;
	u64 err;
	int i;

	if (is_td_in_teardown(kvm_tdx))
		return;

	if (!is_td_initialized(kvm_tdx))
		goto free_hkid;

	err = tdreclaimhkids(kvm_tdx->tdr.pa);
	if (TDX_ERR(err, TDRECLAIMHKIDS))
		return;

	kvm_for_each_vcpu(i, vcpu, (&kvm_tdx->kvm))
		tdx_flush_vp_on_cpu(vcpu);

	err = tdflushvpdone(kvm_tdx->tdr.pa);
	if (TDX_ERR(err, TDFLUSHVPDONE))
		return;

	preempt_disable();
	on_each_cpu_mask(tdx_package_leadcpus, tdx_do_tdwbcache, &err, 1);
	preempt_enable();

	if (unlikely(err))
		return;

	err = tdfreehkids(kvm_tdx->tdr.pa);
	if (TDX_ERR(err, TDFREEHKIDS))
		return;

free_hkid:
	tdx_keyid_free(kvm_tdx->hkid);
	kvm_tdx->hkid = -1;
}

static void tdx_vm_destroy(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	int i;

	/* Can't reclaim or free TD pages if teardown failed. */
	if (!is_td_in_teardown(kvm_tdx))
		return;

	for (i = 0; i < tdx_capabilities.tdcs_nr_pages; i++)
		tdx_reclaim_td_page(&kvm_tdx->tdcs[i]);

	tdx_reclaim_td_page(&kvm_tdx->tdr);
}

struct tdx_tdconfigkey {
	hpa_t tdr;
	int failed;
};

static void tdx_do_tdconfigkey(void *data)
{
	struct tdx_tdconfigkey *configkey = data;
	u64 err;

	err = tdconfigkey(configkey->tdr);
	if (err && cmpxchg(&configkey->failed, 0, 1) == 0)
		TDX_ERR(err, TDCONFIGKEY);
}

static struct kvm *tdx_vm_alloc(void)
{
	struct kvm_tdx *kvm_tdx;

	kvm_tdx = __vmalloc(sizeof(struct kvm_tdx),
			    GFP_KERNEL_ACCOUNT | __GFP_ZERO, PAGE_KERNEL);
	return &kvm_tdx->kvm;
}

static void tdx_vm_free(struct kvm *kvm)
{
	vfree(to_kvm_tdx(kvm));
}

static int tdx_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int cpu, ret, i;

	if (emulate_seam)
		return seam_tdcreatevp(vcpu);

	ret = tdx_alloc_td_page(&tdx->tdvpr);
	if (ret)
		return ret;

	for (i = 0; i < tdx_capabilities.tdvpx_nr_pages; i++) {
		ret = tdx_alloc_td_page(&tdx->tdvpx[i]);
		if (ret)
			goto free_tdvpx;
	}

	tdx->pi_desc.nv = POSTED_INTR_VECTOR;
	tdx->pi_desc.sn = 1;

	cpu = get_cpu();
	list_add(&tdx->cpu_list, &per_cpu(associated_tdvcpus, cpu));
	vcpu->cpu = cpu;
	put_cpu();

	return 0;

free_tdvpx:
	/* @i points at the TDVPX page that failed allocation. */
	for (--i; i >= 0; i--)
		tdx_free_td_page(&tdx->tdvpx[i]);

	tdx_free_td_page(&tdx->tdvpr);

	return ret;
}

static void tdx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (vcpu->cpu != cpu) {
		tdx_flush_vp_on_cpu(vcpu);

		/*
		 * Pairs with the smp_wmb() in tdx_disassociate_vp() to ensure
		 * vcpu->cpu is read before tdx->cpu_list.
		 */
		smp_rmb();

		list_add(&tdx->cpu_list, &per_cpu(associated_tdvcpus, cpu));
	}

	vmx_vcpu_pi_load(vcpu, cpu);
}

static void tdx_vcpu_put(struct kvm_vcpu *vcpu)
{
	vmx_vcpu_pi_put(vcpu);
}

static void tdx_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	int i;

	if (emulate_seam)
		return seam_tdfreevp(vcpu);

	/* Can't reclaim or free pages if teardown failed. */
	if (!is_td_in_teardown(to_kvm_tdx(vcpu->kvm)))
		return;

	for (i = 0; i < tdx_capabilities.tdvpx_nr_pages; i++)
		tdx_reclaim_td_page(&tdx->tdvpx[i]);

	tdx_reclaim_td_page(&tdx->tdvpr);
}

static void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(vcpu->kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct msr_data apic_base_msr;
	u64 err;
	int i;

	if (emulate_seam) {
		seam_tdinitvp(vcpu, init_event);
		return;
	}

	if (WARN_ON(init_event))
		goto td_bugged;

	err = tdcreatevp(kvm_tdx->tdr.pa, tdx->tdvpr.pa);
	if (TDX_ERR(err, TDCREATEVP))
		goto td_bugged;
	tdx_add_td_page(&tdx->tdvpr);

	for (i = 0; i < tdx_capabilities.tdvpx_nr_pages; i++) {
		err = tdaddvpx(tdx->tdvpr.pa, tdx->tdvpx[i].pa);
		if (TDX_ERR(err, TDADDVPX))
			goto td_bugged;
		tdx_add_td_page(&tdx->tdvpx[i]);
	}

	/*
	 * TODO: Plumb an ioctl() to allow userspace to define the initial
	 *       RCX value for the vCPU.  For now, harcode it to zero.
	 */
	err = tdinitvp(tdx->tdvpr.pa, 0);
	if (TDX_ERR(err, TDINITVP))
		goto td_bugged;

	apic_base_msr.data = APIC_DEFAULT_PHYS_BASE | LAPIC_MODE_X2APIC;
	if (kvm_vcpu_is_reset_bsp(vcpu))
		apic_base_msr.data |= MSR_IA32_APICBASE_BSP;
	apic_base_msr.host_initiated = true;
	if (WARN_ON(kvm_set_apic_base(vcpu, &apic_base_msr)))
		goto td_bugged;

	td_vmcs_write16(tdx, POSTED_INTR_NV, POSTED_INTR_VECTOR);
	td_vmcs_write64(tdx, POSTED_INTR_DESC_ADDR, __pa(&tdx->pi_desc));
	td_vmcs_setbit16(tdx, PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR);
	return;

td_bugged:
	vcpu->kvm->vm_bugged = true;
	return;
}

u64 __tdx_vcpu_run(hpa_t tdvpr, void *regs, u32 regs_mask);

static void tdx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (emulate_seam) {
		seam_tdenter(vcpu);
		return;
	}

	/*
	 * TODO:
	 * prepare before TDENTER
	 */

	tdx->exit_reason.full = __tdx_vcpu_run(tdx->tdvpr.pa, vcpu->arch.regs,
					       tdx->tdvmcall.regs_mask);

	if (tdx->exit_reason.error || tdx->exit_reason.non_recoverable)
		return;

	if (tdx->exit_reason.basic == EXIT_REASON_TDCALL)
		tdx->tdvmcall.rcx = vcpu->arch.regs[VCPU_REGS_RCX];
	else
		tdx->tdvmcall.rcx = 0;

	/*
	 * TODO:
	 * after TDENTER
	 */
}

static int tdx_hardware_enable(void)
{
	INIT_LIST_HEAD(&per_cpu(associated_tdvcpus, raw_smp_processor_id()));

	return 0;
}

static void tdx_hardware_disable(void)
{
	int cpu = raw_smp_processor_id();
	struct list_head *tdvcpus = &per_cpu(associated_tdvcpus, cpu);
	struct vcpu_tdx *tdx, *tmp;

	/* Safe variant needed as tdx_disassociate_vp() deletes the entry. */
	list_for_each_entry_safe(tdx, tmp, tdvcpus, cpu_list)
		tdx_disassociate_vp(&tdx->vcpu);
}

static void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	u16 exit_reason = to_tdx(vcpu)->exit_reason.basic;

	if (exit_reason == EXIT_REASON_EXCEPTION_NMI)
		intel_handle_exception_nmi_irqoff(vcpu,
						  tdexit_intr_info(vcpu));
	else if (exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT)
		vmx_handle_external_interrupt_irqoff(vcpu,
						     tdexit_intr_info(vcpu));
}

static int tdx_handle_exception(struct kvm_vcpu *vcpu)
{
	u32 intr_info = tdexit_intr_info(vcpu);

	if (is_nmi(intr_info) || is_machine_check(intr_info))
		return 1;

	kvm_pr_unimpl("unexpected exception 0x%x\n", intr_info);
	return -EFAULT;
}

static int tdx_handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int tdx_handle_triple_fault(struct kvm_vcpu *vcpu)
{
	printk("TDX: %s\n", __func__);
	if (halt_on_triple_fault)
		return kvm_vcpu_halt(vcpu);

	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	vcpu->mmio_needed = 0;
	return 0;
}

static int tdx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	if (emulate_seam)
		return seam_set_msr(vcpu, msr_info);

	return vmx_set_msr(vcpu, msr_info);
}

static int tdx_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;

	eax = tdvmcall_p1_read(vcpu);
	ecx = tdvmcall_p2_read(vcpu);

	kvm_cpuid(to_kvm_vcpu(vcpu), &eax, &ebx, &ecx, &edx, true);

	tdvmcall_p1_write(vcpu, eax);
	tdvmcall_p2_write(vcpu, ebx);
	tdvmcall_p3_write(vcpu, ecx);
	tdvmcall_p4_write(vcpu, edx);

	tdvmcall_set_return_code(vcpu, 0);

	return 1;
}

static int tdx_emulate_hlt(struct kvm_vcpu *vcpu)
{
	printk("TDX: %s\n", __func__);
	tdvmcall_set_return_code(vcpu, 0);

	return kvm_vcpu_halt(to_kvm_vcpu(vcpu));
}

static int tdx_complete_pio_in(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = &vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	int ret;

	BUG_ON(vcpu->arch.pio.count != 1);

	ret = ctxt->ops->pio_in_emulated(ctxt, vcpu->arch.pio.size,
					 vcpu->arch.pio.port, &val, 1);
	WARN_ON(!ret);

	tdvmcall_set_return_code(vcpu, 0);
	tdvmcall_set_return_val(vcpu, val);

	return 1;
}

static int tdx_emulate_io(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = &vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	unsigned port;
	int size, ret;

	++vcpu->stat.io_exits;

	size = tdvmcall_p1_read(vcpu);
	port = tdvmcall_p3_read(vcpu);

	if (size > 4) {
		tdvmcall_set_return_code(vcpu, -E2BIG);
		return 1;
	}

	if (!tdvmcall_p2_read(vcpu)) {
		ret = ctxt->ops->pio_in_emulated(ctxt, size, port, &val, 1);
		if (!ret)
			vcpu->arch.complete_userspace_io = tdx_complete_pio_in;
		else
			tdvmcall_set_return_val(vcpu, val);
	} else {
		val = tdvmcall_p4_read(vcpu);
		ret = ctxt->ops->pio_out_emulated(ctxt, size, port, &val, 1);

		// No need for a complete_userspace_io callback.
		vcpu->arch.pio.count = 0;
	}
	if (ret)
		tdvmcall_set_return_code(vcpu, 0);
	return ret;
}

static int tdx_emulate_vmcall(struct kvm_vcpu *vcpu)
{
	unsigned long nr, a0, a1, a2, a3, ret;

	nr = tdvmcall_exit_reason(vcpu);
	a0 = tdvmcall_p1_read(vcpu);
	a1 = tdvmcall_p2_read(vcpu);
	a2 = tdvmcall_p3_read(vcpu);
	a3 = tdvmcall_p4_read(vcpu);

	ret = __kvm_emulate_hypercall(to_kvm_vcpu(vcpu), nr, a0, a1, a2, a3, true);

	tdvmcall_set_return_code(vcpu, ret);

	return 1;
}

static int tdx_complete_mmio(struct kvm_vcpu *vcpu)
{
	unsigned long val = 0;
	gpa_t gpa;
	int size;

	BUG_ON(vcpu->mmio_needed != 1);
	vcpu->mmio_needed = 0;

	if (!vcpu->mmio_is_write) {
		gpa = vcpu->mmio_fragments[0].gpa;
		size = vcpu->mmio_fragments[0].len;

		memcpy(&val, vcpu->run->mmio.data, size);
		tdvmcall_set_return_val(vcpu, val);
		trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val);
	}
	return 1;
}

static inline int tdx_mmio_write(struct kvm_vcpu *vcpu, gpa_t gpa, int size)
{
	unsigned long val = tdvmcall_p4_read(vcpu);

	if (kvm_iodevice_write(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    kvm_io_bus_write(vcpu, KVM_MMIO_BUS, gpa, size, &val))
		return -EOPNOTSUPP;

	trace_kvm_mmio(KVM_TRACE_MMIO_WRITE, size, gpa, &val);
	return 0;
}

static inline int tdx_mmio_read(struct kvm_vcpu *vcpu, gpa_t gpa, int size)
{
	unsigned long val;

	if (kvm_iodevice_read(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    kvm_io_bus_read(vcpu, KVM_MMIO_BUS, gpa, size, &val))
		return -EOPNOTSUPP;

	tdvmcall_set_return_val(vcpu, val);
	trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val);
	return 0;
}

static int tdx_emulate_mmio(struct kvm_vcpu *vcpu)
{
	struct kvm_memory_slot *slot;
	int size, write, r;
	unsigned long val;
	gpa_t gpa;

	BUG_ON(vcpu->mmio_needed);

	size = tdvmcall_p1_read(vcpu);
	write = tdvmcall_p2_read(vcpu);
	gpa = tdvmcall_p3_read(vcpu);

	if (size > 8u || ((gpa + size - 1) ^ gpa) & PAGE_MASK) {
		tdvmcall_set_return_code(vcpu, -E2BIG);
		return 1;
	}

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gpa >> PAGE_SHIFT);
	if (slot && !(slot->flags & KVM_MEMSLOT_INVALID)) {
		tdvmcall_set_return_code(vcpu, -EFAULT);
		return 1;
	}

	if (!kvm_io_bus_write(vcpu, KVM_FAST_MMIO_BUS, gpa, 0, NULL)) {
		trace_kvm_fast_mmio(gpa);
		return 1;
	}

	if (write)
		r = tdx_mmio_write(vcpu, gpa, size);
	else
		r = tdx_mmio_read(vcpu, gpa, size);
	if (!r) {
		tdvmcall_set_return_code(vcpu, 0);
		return 1;
	}

	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = write;
	vcpu->arch.complete_userspace_io = tdx_complete_mmio;

	vcpu->run->mmio.phys_addr = gpa;
	vcpu->run->mmio.len = size;
	vcpu->run->mmio.is_write = write;
	vcpu->run->exit_reason = KVM_EXIT_MMIO;

	if (write) {
		memcpy(vcpu->run->mmio.data, &val, size);
	} else {
		vcpu->mmio_fragments[0].gpa = gpa;
		vcpu->mmio_fragments[0].len = size;
		trace_kvm_mmio(KVM_TRACE_MMIO_READ_UNSATISFIED, size, gpa, NULL);
	}
	return 0;
}

static int tdx_emulate_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_p1_read(vcpu);
	u64 data;

	if (kvm_get_msr(to_kvm_vcpu(vcpu), index, &data)) {
		trace_kvm_msr_read_ex(index);
		tdvmcall_set_return_code(vcpu, -EFAULT);
		return 1;
	}
	trace_kvm_msr_read(index, data);

	tdvmcall_set_return_code(vcpu, 0);
	tdvmcall_set_return_val(vcpu, data);
	return 1;
}

static int tdx_emulate_wrmsr(struct kvm_vcpu *vcpu)
{
	u32 index = tdvmcall_p1_read(vcpu);
	u64 data = tdvmcall_p2_read(vcpu);

	if (kvm_set_msr(to_kvm_vcpu(vcpu), index, data)) {
		trace_kvm_msr_write_ex(index, data);
		tdvmcall_set_return_code(vcpu, -EFAULT);
		return 1;
	}

	trace_kvm_msr_write(index, data);
	tdvmcall_set_return_code(vcpu, 0);
	return 1;
}

static int tdx_trace_tdvmcall(struct kvm_vcpu *vcpu)
{
	pr_warn("tdvmcall: exit: 0x%lx (%lu, 0x%lx), (%lu, 0x%lx), (%lu, 0x%lx), (%lu, 0x%lx),\n",
		tdvmcall_exit_type(vcpu),
		tdvmcall_p1_read(vcpu), tdvmcall_p1_read(vcpu),
		tdvmcall_p2_read(vcpu), tdvmcall_p2_read(vcpu),
		tdvmcall_p3_read(vcpu), tdvmcall_p3_read(vcpu),
		tdvmcall_p4_read(vcpu), tdvmcall_p4_read(vcpu));

	tdvmcall_set_return_code(vcpu, 0);

	return 1;
}

int handle_tdvmcall(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	unsigned long exit_reason;
	
	//printk("tdx: %s: reason 0x%lx, type: 0x%lx\n",
	//			__func__,
	//			tdvmcall_exit_reason(vcpu),
	//		   	tdvmcall_exit_type(vcpu));

	if (unlikely(tdx->tdvmcall.xmm_mask))
		goto unsupported;

	if (tdvmcall_exit_type(vcpu))
		return tdx_emulate_vmcall(vcpu);

	exit_reason = tdvmcall_exit_reason(vcpu);

	trace_kvm_tdvmcall(vmcs_readl(GUEST_RIP), exit_reason,
			   tdvmcall_p1_read(vcpu), tdvmcall_p2_read(vcpu),
			   tdvmcall_p3_read(vcpu), tdvmcall_p4_read(vcpu));

	switch (exit_reason) {
	case EXIT_REASON_TRIPLE_FAULT:
		return tdx_trace_tdvmcall(vcpu);
	case EXIT_REASON_CPUID:
		return tdx_emulate_cpuid(vcpu);
	case EXIT_REASON_HLT:
		return tdx_emulate_hlt(vcpu);
	// case EXIT_REASON_RDPMC:
	// 	ret = tdx_emulate_rdpmc(vcpu);
	// 	break;
	// case EXIT_REASON_VMCALL:
	// 	
	// 	break;
	case EXIT_REASON_IO_INSTRUCTION:
		return tdx_emulate_io(vcpu);
	case EXIT_REASON_MSR_READ:
		return tdx_emulate_rdmsr(vcpu);
	case EXIT_REASON_MSR_WRITE:
		return tdx_emulate_wrmsr(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_emulate_mmio(vcpu);
	default:
		break;
	}

unsupported:
	tdvmcall_set_return_code(vcpu, -EOPNOTSUPP);
	return 1;
}

static int tdx_handle_ept_violation(struct kvm_vcpu *vcpu)
{
	/* TODO: Use TDX's version of the vCPU to handle MMU stuff. */
	return ept_handle_ept_violation(to_kvm_vcpu(vcpu),
					tdexit_gpa(vcpu),
					tdexit_exit_qual(vcpu));
}

static int tdx_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	WARN_ON(1);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
}

static int tdx_handle_topa_full(struct kvm_vcpu *vcpu)
{
	//WARN_ON(1);
	printk("!! TD EXIT REASON: TOPA_FULL\n");
	vcpu->run->exit_reason = KVM_EXIT_KAFL_TOPA_MAIN_FULL;
	return 0;
}

/*
 * Separate from the top-level exit handler to avoid cyclical recursion, as
 * the SEAM emulator may invoke TDX's exit handler via vmx_handle_exit().
 */
static int __tdx_handle_exit(struct kvm_vcpu *vcpu)
{
	u16 exit_reason = to_tdx(vcpu)->exit_reason.basic;

	switch (exit_reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		return tdx_handle_exception(vcpu);
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return tdx_handle_external_interrupt(vcpu);
	case EXIT_REASON_TRIPLE_FAULT:
		return tdx_handle_triple_fault(vcpu);
	case EXIT_REASON_TDCALL:
		return handle_tdvmcall(vcpu);
	case EXIT_REASON_EPT_VIOLATION:
		return tdx_handle_ept_violation(vcpu);
	case EXIT_REASON_EPT_MISCONFIG:
		return tdx_handle_ept_misconfig(vcpu);
	case KVM_EXIT_KAFL_TOPA_MAIN_FULL: /* PT TOPA_FULL */
		return tdx_handle_topa_full(vcpu);
	default:
		break;
	}

	kvm_pr_unimpl("unexpected exit reason 0x%x\n", exit_reason);
	return -EFAULT;
}

static int tdx_handle_exit(struct kvm_vcpu *vcpu,
			   enum exit_fastpath_completion fastpath)
{
	WARN_ON_ONCE(fastpath != EXIT_FASTPATH_NONE);

	return __tdx_handle_exit(vcpu);
}

static bool tdx_is_emulatable(struct kvm_vcpu *vcpu, void *insn, int insn_len)
{
	if (emulate_seam)
		return seam_is_emulatable(vcpu, insn, insn_len);

	return false;
}

static int __init tdx_check_processor_compatibility(void)
{
	if (emulate_seam)
		return seam_check_processor_compat();

	/* TDX-SEAM itself verifies compatibility on all CPUs. */
	return 0;
}

static void tdx_set_virtual_apic_mode(struct kvm_vcpu *vcpu)
{
	WARN_ON_ONCE(kvm_get_apic_mode(vcpu) != LAPIC_MODE_X2APIC);
}

static void tdx_apicv_post_state_restore(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	pi_clear_on(&tdx->pi_desc);
	memset(tdx->pi_desc.pir, 0, sizeof(tdx->pi_desc.pir));
}

static int tdx_sync_pir_to_irr(struct kvm_vcpu *vcpu)
{
	/*
	 * TODO:
	 * KVM-TDX cannot access irr, it should be done by TDX-SEAM module.
	 * On the other hand, this function is called in
	 *	apic_has_interrupt_for_ppr()
	 * and it's supposed to return the highest irr. I'm not sure whether
	 * it will go to this path in TDX.
	 */
	return -1;
}

/*
 * Send interrupt to vcpu via posted interrupt way.
 * 1. If target vcpu is running(non-root mode), send posted interrupt
 * notification to vcpu and hardware will sync PIR to vIRR atomically.
 * 2. If target vcpu isn't running(root mode), kick it to pick up the
 * interrupt from PIR in next vmentry.
 */
static void tdx_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (pi_test_and_set_pir(vector, &tdx->pi_desc))
		return;

	/* If a previous notification has sent the IPI, nothing to do. */
	if (pi_test_and_set_on(&tdx->pi_desc))
		return;

	if (!kvm_vcpu_trigger_posted_interrupt(vcpu, false))
		kvm_vcpu_kick(vcpu);
}

static int __init setup_tdx_capabilities(struct tdx_capabilities *tdx_caps)
{
	struct tdsysinfo_struct *tdsysinfo = tdx_get_sysinfo();

	if (tdsysinfo == NULL) {
		WARN_ON_ONCE(boot_cpu_has(X86_FEATURE_TDX));
		return -ENODEV;
	}

	tdx_caps->tdcs_nr_pages = tdsysinfo->tdcs_base_size / PAGE_SIZE;
	if (tdx_caps->tdcs_nr_pages != TDX1_NR_TDCX_PAGES)
		return -EIO;

	tdx_caps->tdvpx_nr_pages = tdsysinfo->tdvps_base_size / PAGE_SIZE - 1;
	if (tdx_caps->tdvpx_nr_pages != TDX1_NR_TDVPX_PAGES)
		return -EIO;

	tdx_caps->attrs_fixed0 = tdsysinfo->attributes_fixed0;
	tdx_caps->attrs_fixed1 = tdsysinfo->attributes_fixed1;
	tdx_caps->xfam_fixed0 =	tdsysinfo->xfam_fixed0;
	tdx_caps->xfam_fixed1 = tdsysinfo->xfam_fixed1;

	tdx_caps->nr_cpuid_configs = tdsysinfo->num_cpuid_config;
	if (tdx_caps->nr_cpuid_configs > TDX1_MAX_NR_CPUID_CONFIGS)
		return -EIO;

	if (!memcpy(tdx_caps->cpuid_configs, tdsysinfo->cpuid_configs,
		    tdsysinfo->num_cpuid_config * sizeof(struct tdx_cpuid_config)))
		return -EIO;

	return 0;
}

static int __init tdx_hardware_setup(void)
{
	if (emulate_seam)
		return seam_hardware_setup();

	return setup_tdx_capabilities(&tdx_capabilities);
}

/*
 * TDX-SEAM definitions for fixed{0,1} are inverted relative to VMX.  The TDX
 * definitions are sane, the VMX definitions are backwards.
*/
static inline bool tdx_fixed_bits_valid(u64 val, u64 fixed0, u64 fixed1)
{
	return ((val & fixed0) | fixed1) == val;
}

static struct kvm_cpuid_entry2 *tdx_find_cpuid_entry(struct kvm_tdx *kvm_tdx,
						     u32 function, u32 index)
{
	struct kvm_cpuid_entry2 *entry;
	int i;

	for (i = 0; i < kvm_tdx->cpuid_nent; i++) {
		entry = &kvm_tdx->cpuid_entries[i];

		if (is_matching_cpuid_entry(entry, function, index))
			return entry;
	}
	return NULL;
}

static int setup_tdparams(struct kvm *kvm, struct td_params *td_params)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_cpuid_config *config;
	struct kvm_cpuid_entry2 *entry;
	struct tdx_cpuid_value *value;
	u64 guest_supported_xcr0;
	u64 guest_supported_xss;
	u32 guest_tsc_khz;
	int max_pa;
	int i;

	td_params->max_vcpus = kvm->max_vcpus;

	/* TODO: Enforce consistent CPUID features for all vCPUs. */
	for (i = 0; i < tdx_capabilities.nr_cpuid_configs; i++) {
		config = &tdx_capabilities.cpuid_configs[i];

		entry = tdx_find_cpuid_entry(kvm_tdx, config->leaf,
					     config->sub_leaf);
		if (!entry)
			continue;

		/*
		 * Non-configurable bits must be '0', even if they are fixed to
		 * '1' by TDX-SEAM, i.e. mask off non-configurable bits.
		 */
		value = &td_params->cpuid_values[i];
		value->eax = entry->eax & config->eax;
		value->ebx = entry->ebx & config->ebx;
		value->ecx = entry->ecx & config->ecx;
		value->edx = entry->edx & config->edx;
	}

	/*
	 * TODO: Thse needs to be masked against kvm_supported_xcr0/xss(), but
	 * the former isn't supported and the latter doesn't exist.  That's
	 * changing in 5.7, so don't bother for now.
	 */
	entry = tdx_find_cpuid_entry(kvm_tdx, 0xd, 0);
	if (entry)
		guest_supported_xcr0 = (entry->eax | ((u64)entry->edx << 32));
	else
		guest_supported_xcr0 = 0;

	entry = tdx_find_cpuid_entry(kvm_tdx, 0xd, 1);
	if (entry)
		guest_supported_xss = (entry->ecx | ((u64)entry->edx << 32));
	else
		guest_supported_xss = 0;

	max_pa = 36;
	entry = tdx_find_cpuid_entry(kvm_tdx, 0x80000008, 0);
	if (entry)
		max_pa = entry->eax & 0xff;

	td_params->eptp_controls = VMX_EPTP_MT_WB;

	if (cpu_has_vmx_ept_5levels() && max_pa > 48) {
		td_params->eptp_controls |= VMX_EPTP_PWL_5;
		td_params->exec_controls = 1;
	} else {
		td_params->eptp_controls |= VMX_EPTP_PWL_4;
		td_params->exec_controls = 0;
	}

	/* TODO
	 * We need to setup td_params->attributes; (TD Debug, KL & PERFMON)
	 * based on tdx_capabilities->attributes_fixed0;
	 *	    tdx_capabilities->attributes_fixed1;
	 */
	if (!tdx_fixed_bits_valid(td_params->attributes,
				  tdx_capabilities.attrs_fixed0,
				  tdx_capabilities.attrs_fixed1))
		return -EINVAL;

	/* Setup td_params.xfam */
	td_params->xfam = guest_supported_xcr0 | guest_supported_xss;
	if (!tdx_fixed_bits_valid(td_params->xfam,
				  tdx_capabilities.xfam_fixed0,
				  tdx_capabilities.xfam_fixed1))
		return -EINVAL;

	/* TODO: Support a scaled guest TSC, i.e. take this from userspace. */
	guest_tsc_khz = tsc_khz;
	if (guest_tsc_khz < TDX1_MIN_TSC_FREQUENCY_KHZ ||
	    guest_tsc_khz > TDX1_MAX_TSC_FREQUENCY_KHZ)
		return -EINVAL;

	td_params->tsc_frequency = TDX1_TSC_KHZ_TO_TDPARAMS(guest_tsc_khz);

	/* TODO
	 *  - MRCONFIGID
	 *  - MROWNER
	 *  - MROWNERCONFIG
	 */
	return 0;
}

static int tdx_td_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_cpuid2 __user *user_cpuid = (void *)cmd->data;
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct td_params *td_params;
	struct tdx_ex_ret ex_ret;
	struct kvm_cpuid2 cpuid;
	int ret;
	u64 err;

	if (cmd->metadata > KVM_MAX_VCPUS)
		return -EINVAL;

	if (copy_from_user(&cpuid, user_cpuid, sizeof(cpuid)))
		return -EFAULT;

	if (cpuid.nent > KVM_MAX_CPUID_ENTRIES)
		return -E2BIG;

	if (copy_from_user(&kvm_tdx->cpuid_entries, user_cpuid->entries,
			   cpuid.nent * sizeof(struct kvm_cpuid_entry2)))
		return -EFAULT;

	kvm->max_vcpus = cmd->metadata;

	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

	td_params = kzalloc(sizeof(struct td_params), GFP_KERNEL_ACCOUNT);
	if (!td_params)
		return -ENOMEM;

	kvm_tdx->cpuid_nent = cpuid.nent;

	ret = setup_tdparams(kvm, td_params);
	if (ret)
		goto free_tdparams;

	err = tdinit(kvm_tdx->tdr.pa, __pa(td_params), &ex_ret);
	if (TDX_ERR(err, TDINIT))
		ret = -EIO;

free_tdparams:
	kfree(td_params);
	if (ret) {
		kvm_tdx->cpuid_nent = 0;
		kvm->max_vcpus = 0;
	}
	return ret;
}

static int tdx_init_mem_region(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct kvm_tdx_init_mem_region region;
	struct tdx_ex_ret ex_ret;
	hpa_t src_hpa, dest_hpa;
	struct page *page;
	u64 err;
	int ret;

	if (cmd->metadata)
		return -EINVAL;

	if (copy_from_user(&region, (void __user *)cmd->data, sizeof(region)))
		return -EFAULT;

	/* Sanity check */
	if (!IS_ALIGNED(region.source_addr, PAGE_SIZE))
		return -EINVAL;
	if (!IS_ALIGNED(region.gpa, PAGE_SIZE))
		return -EINVAL;
	if (region.gpa + (region.nr_pages << PAGE_SHIFT) < region.gpa)
		return -EINVAL;

	ret = 0;
	while (region.nr_pages) {
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		if (need_resched())
			cond_resched();

		ret = get_user_pages_fast(region.source_addr, 1, 0, &page);
		if (ret < 0)
			break;

		if (ret != 1) {
			ret = -ENOMEM;
			break;
		}

		dest_hpa = pfn_to_hpa(gfn_to_pfn(kvm, gpa_to_gfn(region.gpa)));
		src_hpa = pfn_to_hpa(page_to_pfn(page));

		err = tdaddpage(kvm_tdx->tdr.pa, region.gpa, dest_hpa, src_hpa,
				&ex_ret);
		put_page(page);
		if (TDX_ERR(err, TDADDPAGE)) {
			ret = -EIO;
			break;
		}

		region.source_addr += PAGE_SIZE;
		region.gpa += PAGE_SIZE;
		region.nr_pages--;
	}

	if (copy_to_user((void __user *)cmd->data, &region, sizeof(region)))
		ret = -EFAULT;

	return ret;
}

static int tdx_vm_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_tdx_cmd tdx_cmd;
	int r;

	if (copy_from_user(&tdx_cmd, argp, sizeof(struct kvm_tdx_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	switch (tdx_cmd.id) {
	case KVM_TDX_INIT:
		r = tdx_td_init(kvm, &tdx_cmd);
		break;
	case KVM_TDX_INIT_MEM_REGION:
		r = tdx_init_mem_region(kvm, &tdx_cmd);
		break;
	default:
		r = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &tdx_cmd, sizeof(struct kvm_tdx_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

static void __init tdx_early_init(unsigned int *vcpu_size,
				  unsigned int *vcpu_align)
{
	if (!enable_tdx)
		emulate_seam = 0;

	if (emulate_seam) {
		seam_early_init(vcpu_size, vcpu_align);
		return;
	}

	*vcpu_size = sizeof(struct vcpu_tdx);
	*vcpu_align = __alignof__(struct vcpu_tdx);
}

static int __init tdx_init(void)
{
	if (seam_module)
		return seam_load_module_from_path(seam_module);

	return 0;
}

static void tdx_exit(void)
{

}

static long seamcall_direct(struct kvm_seamcall_regs *regs,
			    struct tdx_ex_ret *ex)
{
	seamcall_5_5(regs->rax, regs->rcx, regs->rdx, regs->r8, regs->r9,
		     regs->r10, ex);
};

static void tdx_do_seamcall(struct kvm_seamcall *call)
{
	struct tdx_ex_ret ex;

	call->out.rax = seamcall_direct(&call->in, &ex);
	call->out.rcx = ex.rcx;
	call->out.rdx = ex.rdx;
	call->out.r8  = ex.r8;
	call->out.r9  = ex.r9;
	call->out.r10 = ex.r10;
}

static void tdx_do_tdenter(struct kvm_tdenter *tdenter)
{
	union tdx_exit_reason exit_reason;
	u64 *regs = tdenter->regs;

	preempt_disable();
	local_irq_disable();

	exit_reason.full = __tdx_vcpu_run(regs[VCPU_REGS_RAX], regs,
					  regs[VCPU_REGS_RCX]);

	/* __tdx_vcpu_run() doesn't bother saving RAX. */
	regs[VCPU_REGS_RAX] = exit_reason.full;
	if (exit_reason.error || exit_reason.non_recoverable)
		goto out;

	if (exit_reason.basic == EXIT_REASON_EXCEPTION_NMI &&
	    is_nmi(regs[VCPU_REGS_R9])) {
		asm("int $2");
	} else if (exit_reason.basic == EXIT_REASON_EXTERNAL_INTERRUPT)
		vmx_handle_external_interrupt_irqoff(NULL,
						     regs[VCPU_REGS_R9]);

out:
	local_irq_enable();
	preempt_enable();
}

#else /* CONFIG_KVM_INTEL_TDX */

static int tdx_vm_init(struct kvm *kvm) { return 0; }
static void tdx_vm_teardown(struct kvm *kvm) {}
static void tdx_vm_destroy(struct kvm *kvm) {}
static struct kvm *tdx_vm_alloc(void) { return NULL; }
static void tdx_vm_free(struct kvm *kvm) {}
static int tdx_vcpu_create(struct kvm_vcpu *vcpu) { return 0; }
static void tdx_vcpu_free(struct kvm_vcpu *vcpu) {}
static void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event) {}
static void tdx_vcpu_run(struct kvm_vcpu *vcpu) {}
static void tdx_vcpu_load(struct kvm_vcpu *vcpu, int cpu) {}
static void tdx_vcpu_put(struct kvm_vcpu *vcpu) {}
static int tdx_hardware_enable(void) { return 0; }
static void tdx_hardware_disable(void) {}
static void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu) {}
static int tdx_handle_exit(struct kvm_vcpu *vcpu,
			   enum exit_fastpath_completion fastpath) { return 0; }
static int tdx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info) { return 0; }
static bool tdx_is_emulatable(struct kvm_vcpu *vcpu, void *insn, int insn_len) { return false; }
static int tdx_vm_ioctl(struct kvm *kvm, void __user *argp) { return 0; }
static void tdx_set_virtual_apic_mode(struct kvm_vcpu *vcpu) {}
static void tdx_apicv_post_state_restore(struct kvm_vcpu *vcpu) {}
static int tdx_sync_pir_to_irr(struct kvm_vcpu *vcpu) { return 0; }
static void tdx_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector) {}
static int __init tdx_check_processor_compatibility(void) { return 0; }
static int __init tdx_hardware_setup(void) { return 0; }
static void __init tdx_early_init(unsigned int *vcpu_size,
				  unsigned int *vcpu_align) {}
static int __init tdx_init(void) { return 0; }
static void tdx_exit(void) {}

#endif
