// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/jump_label.h>
#include <linux/trace_events.h>
#include <linux/pagemap.h>

#include <asm/kvm_boot.h>
#include <asm/virtext.h>

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
	return phys_to_virt(to_tdx(vcpu)->tdvpr);
}

static __always_inline unsigned long seamret_exit_reason(struct kvm_vcpu *vcpu)
{
	return kvm_rax_read(vcpu);
}
static __always_inline unsigned long seamret_exit_qual(struct kvm_vcpu *vcpu)
{
	return kvm_rcx_read(vcpu);
}
static __always_inline unsigned long seamret_gpa(struct kvm_vcpu *vcpu)
{
	return kvm_r8_read(vcpu);
}
static __always_inline unsigned long seamret_sept_hpa(struct kvm_vcpu *vcpu)
{
	return kvm_r9_read(vcpu);
}
static __always_inline unsigned long seamret_intr_info(struct kvm_vcpu *vcpu)
{
	return kvm_r10_read(vcpu);
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

static int tdx_vm_init(struct kvm *kvm)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	u8 i;

	kvm->arch.shadow_mmio_value = 0;

	kvm_tdx->tdr = INVALID_PAGE;
	for (i = 0; i < tdx_capabilities.tdcs_nr_pages; i++)
		kvm_tdx->tdcs[i] = INVALID_PAGE;

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

static void tdx_vm_destroy(struct kvm *kvm)
{
	if (emulate_seam) {
		seam_tdteardown(kvm);
		return;
	}

	/*
	 * TODO:
	 * SEAMCALL(TDFREEHKIDS);
	 * SEAMCALL(TDTEARDOWN)
	 */
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
	u8 i;

	if (emulate_seam)
		return seam_tdcreatevp(vcpu);

	tdx->tdvpr = INVALID_PAGE;
	for (i = 0; i < tdx_capabilities.tdvpx_nr_pages; i++)
		tdx->tdvpx[i] = INVALID_PAGE;

	tdx->cpu = -1;

	tdx->pi_desc.nv = POSTED_INTR_VECTOR;
	tdx->pi_desc.sn = 1;

	return 0;
}

static void tdx_vcpu_free(struct kvm_vcpu *vcpu)
{
	if (emulate_seam)
		return seam_tdfreevp(vcpu);

	/*
	 * TODO:
	 * SEAMCALL(TDRECLAIMPAGE)
	 * SEAMCALL(TDREMOVEPAGE)
	 */
}

static void tdx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct msr_data apic_base_msr;

	if (emulate_seam) {
		seam_tdinitvp(vcpu, init_event);
		return;
	}

	/*
	 * TODO:
	 * SEAMCALL(TDFINALIZEMR)
	 * SEAMCALL(TDINITVP)
	 */

	if (WARN_ON(init_event))
		return;

	apic_base_msr.data = APIC_DEFAULT_PHYS_BASE | LAPIC_MODE_X2APIC;
	if (kvm_vcpu_is_reset_bsp(vcpu))
		apic_base_msr.data |= MSR_IA32_APICBASE_BSP;
	apic_base_msr.host_initiated = true;
	WARN_ON(kvm_set_apic_base(vcpu, &apic_base_msr));
}

static void tdx_flush_vp(void *arg)
{
	struct vcpu_tdx *tdx = arg;
	u64 err;

	if (tdx->cpu != raw_smp_processor_id() ||
	    WARN_ON_ONCE(tdx->tdvpr == INVALID_PAGE))
		return;

	err = tdflushvp(tdx->tdvpr);
	if (unlikely(err && err != TDX_VCPU_NOT_ASSOCIATED))
		TDX_ERR(err, TDFLUSHVP);

	list_del(&tdx->cpu_list);

	/*
	 * Ensure tdx->cpu_list is updated is before setting tdx->cpu to -1,
	 * otherwise, a different CPU can see tdx->cpu = -1 and add the vCPU to
	 * its list before its deleted from this CPUs list.
	 */
	smp_wmb();

	tdx->cpu = -1;
}

static void tdx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);

	if (tdx->cpu != cpu) {
		if (tdx->cpu != -1)
			smp_call_function_single(tdx->cpu, tdx_flush_vp, tdx, 1);

		/*
		 * Pairs with the smp_wmb() in tdx_flush_vp() to ensure
		 * tdx->cpu is read before tdx->cpu_list.
		 */
		smp_rmb();

		list_add(&tdx->cpu_list, &per_cpu(associated_tdvcpus, cpu));

		tdx->cpu = cpu;
	}

	vmx_vcpu_pi_load(vcpu, cpu);
}

static void tdx_vcpu_put(struct kvm_vcpu *vcpu)
{
	vmx_vcpu_pi_put(vcpu);
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

	tdx->exit_reason.full = __tdx_vcpu_run(tdx->tdvpr, vcpu->arch.regs,
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

	/* Safe variant needed as tdx_flush_vp() deletes the entry. */
	list_for_each_entry_safe(tdx, tmp, tdvcpus, cpu_list)
		tdx_flush_vp(tdx);
}

static void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	u32 exit_reason = seamret_exit_reason(vcpu);

	if (exit_reason == EXIT_REASON_EXCEPTION_NMI)
		vmx_handle_exception_nmi_irqoff(vcpu,
			seamret_intr_info(vcpu));
	else if (exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT)
		vmx_handle_external_interrupt_irqoff(vcpu,
			seamret_intr_info(vcpu));
}

static int tdx_handle_exception(struct kvm_vcpu *vcpu)
{
	u32 intr_info = seamret_intr_info(vcpu);

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

	if (!kvm_io_bus_write(vcpu, KVM_FAST_MMIO_BUS, gpa, 0, NULL)) {
		trace_kvm_fast_mmio(gpa);
		return 1;
	}

	r = __kvm_mmu_page_fault(to_kvm_vcpu(vcpu), gpa, PFERR_RSVD_MASK, &r);
	if (r) {
		tdvmcall_set_return_code(vcpu, -EFAULT);
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
	pr_warn("tdvmcall: (%lu, 0x%lx), (%lu, 0x%lx), (%lu, 0x%lx), (%lu, 0x%lx),\n",
		tdvmcall_p1_read(vcpu), tdvmcall_p1_read(vcpu),
		tdvmcall_p2_read(vcpu), tdvmcall_p2_read(vcpu),
		tdvmcall_p3_read(vcpu), tdvmcall_p3_read(vcpu),
		tdvmcall_p4_read(vcpu), tdvmcall_p4_read(vcpu));

	tdvmcall_set_return_code(vcpu, 0);

	return 1;
}

static int handle_tdvmcall(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	unsigned long exit_reason;

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
		break;
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
					seamret_gpa(vcpu),
					seamret_exit_qual(vcpu));
}

static int tdx_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	WARN_ON(1);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
}

/*
 * Separate from the top-level exit handler to avoid cyclical recursion, as
 * the SEAM emulator may invoke TDX's exit handler via vmx_handle_exit().
 */
static int __tdx_handle_exit(struct kvm_vcpu *vcpu)
{
	u32 exit_reason = seamret_exit_reason(vcpu);

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

static inline bool is_td_vcpu_initialized(struct vcpu_tdx *tdx)
{
	return tdx->tdvpr != INVALID_PAGE;
}

static inline bool is_td_guest_initialized(struct kvm_tdx *kvm_tdx)
{
	return kvm_tdx->tdr != INVALID_PAGE;
}

static int tdx_td_vcpu_init(struct kvm *kvm, struct kvm_vcpu *vcpu)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct tdx_ex_ret ex_ret;
	unsigned long page;
	u64 err;
	int ret;
	u8 i;

	if (WARN_ON(is_td_vcpu_initialized(tdx)))
		return -EINVAL;

	/* SEAMCALL(TDCREATEVP) */
	page = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!page)
		return -ENOMEM;

	err = tdcreatevp(kvm_tdx->tdr, tdx->tdvpr);
	if (TDX_ERR(err, TDCREATEVP)) {
		ret = -EIO;
		goto free_tdvpr;
	}

	/* SEAMCALL(TDADDVPX) */
	for (i = 0; i < tdx_capabilities.tdvpx_nr_pages; i++) {
		page = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!page)
			goto free_tdvpx;
		else
			tdx->tdvpx[i] = __pa(page);
	}

	for (i = 0; i < tdx_capabilities.tdvpx_nr_pages; i++) {
		err = tdaddvpx(tdx->tdvpr, tdx->tdvpx[i]);
		if (TDX_ERR(err, TDADDVPX)) {
			ret = -EIO;
			goto reclaim_tdvpx;
		}
	}

	/* SEAMCALL(TDINITVP) */
	/*
	 * TODO: Plumb an ioctl() to allow userspace to define the initial
	 *       RCX value for the vCPU.  For now, harcode it to zero.
	 */
	err = tdinitvp(tdx->tdvpr, 0);
	if (TDX_ERR(err, TDINITVP)) {
		ret = -EIO;
		goto reclaim_tdvpx;
	}

	/* TODO: Configure posted interrupts in TDVPS. */
	td_vmcs_write16(tdx, POSTED_INTR_NV, POSTED_INTR_VECTOR);
	td_vmcs_write64(tdx, POSTED_INTR_DESC_ADDR, __pa(&tdx->pi_desc));
	td_vmcs_setbit16(tdx, PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR);
	return 0;

reclaim_tdvpx:
	/* @i points at the TDVPX page that failed tdaddvpx().
	 *
	 * If tdaddvpx() succeeds, TDX-SEAM zeros out the TDVPX page contents
	 * using direct writes(MOVDIR64B).  MOVDIR64B ensures no cache line is
	 * valid for the TDVPX page, so there's no need for tdwbinvdpage().
	 */
	while (i--) {
		if (tdx->tdvpx[i] != INVALID_PAGE)
			BUG_ON(tdreclaimpage(tdx->tdvpx[i], &ex_ret));
	}
	BUG_ON(tdwbinvdpage(tdx->tdvpr));
free_tdvpx:
	for (i = 0; i < tdx_capabilities.tdvpx_nr_pages; i++) {
		if (tdx->tdvpx[i] != INVALID_PAGE) {
			free_page((unsigned long)__va(tdx->tdvpx[i]));
			tdx->tdvpx[i] = INVALID_PAGE;
		}
	}
	BUG_ON(tdreclaimpage(tdx->tdvpr, &ex_ret));
free_tdvpr:
	free_page((unsigned long)__va(tdx->tdvpr));
	tdx->tdvpr = INVALID_PAGE;
	return ret;
}

static void tdx_td_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	struct vcpu_tdx *tdx = to_tdx(vcpu);
	struct tdx_ex_ret ex_ret;
	u8 i;

	if (!is_td_vcpu_initialized(tdx))
		return;

	for (i = 0; i < tdx_capabilities.tdvpx_nr_pages; i++) {
		if (tdx->tdvpx[i] != INVALID_PAGE) {
			BUG_ON(tdwbinvdpage(tdx->tdvpx[i]));
			BUG_ON(tdreclaimpage(tdx->tdvpx[i], &ex_ret));
			free_page((unsigned long)__va(tdx->tdvpx[i]));
			tdx->tdvpx[i] = INVALID_PAGE;
		}
	}

	BUG_ON(tdwbinvdpage(tdx->tdvpr));
	BUG_ON(tdreclaimpage(tdx->tdvpr, &ex_ret));
	free_page((unsigned long)__va(tdx->tdvpr));
	tdx->tdvpr = INVALID_PAGE;
}

static int tdx_td_vcpu_init_all(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i, ret;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		ret = tdx_td_vcpu_init(kvm, vcpu);
		if (ret)
			goto td_vcpu_uninit;
	}
	return 0;

td_vcpu_uninit:
	kvm_for_each_vcpu(i, vcpu, kvm)
		tdx_td_vcpu_uninit(vcpu);

	return ret;
}

static int __init setup_tdx_capabilities(struct tdx_capabilities *tdx_caps)
{
	struct tdsysinfo_struct *tdsysinfo = tdx_get_sysinfo();

	if (tdsysinfo == NULL) {
		pr_err("TDX-SEAM module havsn't been loaded or initialized!\n");
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

struct tdx_tdconfigkey {
	hpa_t tdr;
	int error_code;
};

static void tdx_do_tdconfigkey(void *data)
{
	struct tdx_tdconfigkey *configkey = data;
	u64 err;

	err = tdconfigkey(configkey->tdr);
	if (err && cmpxchg(&configkey->error_code, 0, -EFAULT) == 0)
		TDX_ERR(err, TDCONFIGKEY);
}

/*
 * TDX-SEAM definitions for fixed{0,1} are inverted relative to VMX.  The TDX
 * definitions are sane, the VMX definitions are backwards.
*/
static inline bool tdx_fixed_bits_valid(u64 val, u64 fixed0, u64 fixed1)
{
	return ((val & fixed0) | fixed1) == val;
}

static int setup_tdparams(struct kvm *kvm, struct td_params *td_params)
{
	struct kvm_vcpu *vcpu = kvm_get_vcpu(kvm, 0);
	struct tdx_cpuid_config *config;
	struct kvm_cpuid_entry2 *entry;
	struct tdx_cpuid_value *value;
	int i;

	td_params->max_vcpus = atomic_read(&kvm->online_vcpus);
	td_params->eptp_controls = VMX_EPTP_MT_WB;

	/* TODO: Make max PA a property of the TD and enforce it for each vCPU. */
	if (cpu_has_vmx_ept_5levels() && vcpu->arch.maxphyaddr > 48) {
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
	td_params->xfam = vcpu->arch.guest_supported_xcr0 |
			  vcpu->arch.guest_supported_xss;
	if (!tdx_fixed_bits_valid(td_params->xfam,
				  tdx_capabilities.xfam_fixed0,
				  tdx_capabilities.xfam_fixed1))
		return -EINVAL;

	/* Setup td_params.cpuid_values */
	for (i = 0; i < tdx_capabilities.nr_cpuid_configs; i++) {
		config = &tdx_capabilities.cpuid_configs[i];

		entry = kvm_find_cpuid_entry(vcpu, config->leaf,
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

	/* TODO
	 * 1. TSC_FREQUENCY
	 * 2. MRCONFIGID
	 * 3. MROWNER
	 * 4. MROWNERCONFIG
	 */
	return 0;
}

static int tdx_guest_init(struct kvm *kvm, struct kvm_tdx_cmd *cmd)
{
	struct kvm_tdx *kvm_tdx = to_kvm_tdx(kvm);
	struct tdx_tdconfigkey configkey;
	struct tdx_ex_ret ex_ret;
	struct td_params *td_params;
	unsigned long page;
	int ret, hkid;
	u64 err;
	u8 i;

	if (is_td_guest_initialized(kvm_tdx))
		return -EINVAL;

	hkid = tdx_keyid_alloc();
	if (hkid < 0)
		return -ENOKEY;

	/* SEAMCALL(TDCREATE) */
	page = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!page) {
		ret = -ENOMEM;
		goto free_hkid;
	}

	kvm_tdx->tdr = __pa(page);
	err = tdcreate(kvm_tdx->tdr, hkid);
	if (TDX_ERR(err, TDCREATE)) {
		ret = -EIO;
		goto free_tdr_page;
	}

	/* SEAMCALL(TDCONFIGKEY) */
	configkey.tdr = kvm_tdx->tdr;
	configkey.error_code = 0;

	preempt_disable();
	on_each_cpu_mask(tdx_package_leadcpus, tdx_do_tdconfigkey, &configkey, 1);
	preempt_enable();

	if (configkey.error_code) {
		ret = configkey.error_code;
		goto reclaim_tdr;
	}

	/* SEAMCAL(TDADDCX) */
	ret = -ENOMEM;
	for (i = 0; i < tdx_capabilities.tdcs_nr_pages; i++) {
		page = __get_free_page(GFP_KERNEL_ACCOUNT);
		if (!page)
			goto free_tdcs;
		else
			kvm_tdx->tdcs[i] = __pa(page);
	}

	for (i = 0; i < tdx_capabilities.tdcs_nr_pages; i++) {
		err = tdaddcx(kvm_tdx->tdr, kvm_tdx->tdcs[i]);
		if (TDX_ERR(err, TDADDCX)) {
			ret = -EIO;
			goto reclaim_tdcs;
		}
	}

	/* SEAMCALL(TDINIT) */
	BUILD_BUG_ON(sizeof(struct td_params) != 1024);

	td_params = kzalloc(sizeof(struct td_params), GFP_KERNEL_ACCOUNT);
	if (!td_params)
		goto reclaim_tdcs;

	ret = setup_tdparams(kvm, td_params);
	if (ret)
		goto free_tdparams;

	err = tdinit(kvm_tdx->tdr, __pa(td_params), &ex_ret);
	if (TDX_ERR(err, TDINIT)) {
		ret = -EIO;
		goto free_tdparams;
	}

	ret = tdx_td_vcpu_init_all(kvm);
	if (ret)
		goto reclaim_hkids;

	kfree(td_params);
	return 0;

reclaim_hkids:
	err = tdreclaimhkids(kvm_tdx->tdr);
	if (TDX_ERR(err, TDRECLAIMHKIDS))
		return -EIO;

	/*
	 * TODO: TDFLUSHVP, TDFLUSHVPDONE, TDWBCACHE (if necessary, there is no
	 *       TD vCPU running at this point).
	 */
	err = tdfreehkids(kvm_tdx->tdr);
	if (TDX_ERR(err, TDFREEHKIDS))
		return -EIO;

free_tdparams:
	kfree(td_params);
reclaim_tdcs:
	/* @i points at the TDCS page that failed tdaddcx(). */
	while (i--) {
		if (kvm_tdx->tdcs[i]) {
			BUG_ON(tdreclaimpage(kvm_tdx->tdcs[i], &ex_ret));
			BUG_ON(tdwbinvdpage(kvm_tdx->tdcs[i]));
		}
	}
free_tdcs:
	for (i = 0; i < tdx_capabilities.tdcs_nr_pages; i++) {
		if (kvm_tdx->tdcs[i] != INVALID_PAGE) {
			free_page((unsigned long)__va(kvm_tdx->tdcs[i]));
			kvm_tdx->tdcs[i] = INVALID_PAGE;
		}
	}
reclaim_tdr:
	BUG_ON(tdreclaimpage(kvm_tdx->tdr, &ex_ret));
	BUG_ON(tdwbinvdpage(kvm_tdx->tdr));
free_tdr_page:
	free_page((unsigned long)__va(kvm_tdx->tdr));
	kvm_tdx->tdr = INVALID_PAGE;
free_hkid:
	tdx_keyid_free(hkid);
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

		err = tdaddpage(kvm_tdx->tdr, region.gpa, dest_hpa, src_hpa, &ex_ret);
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

	if (tdx_cmd.reserved)
		return -EINVAL;

	mutex_lock(&kvm->lock);

	switch (tdx_cmd.id) {
	case KVM_TDX_INIT:
		r = tdx_guest_init(kvm, &tdx_cmd);
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
	    is_nmi(regs[VCPU_REGS_R10])) {
		asm("int $2");
	} else if (exit_reason.basic == EXIT_REASON_EXTERNAL_INTERRUPT)
		vmx_handle_external_interrupt_irqoff(NULL,
						     regs[VCPU_REGS_R10]);

out:
	local_irq_enable();
	preempt_enable();
}

#else /* CONFIG_KVM_INTEL_TDX */

static int tdx_vm_init(struct kvm *kvm) { return 0; }
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
