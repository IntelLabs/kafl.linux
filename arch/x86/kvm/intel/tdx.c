// SPDX-License-Identifier: GPL-2.0
#include <linux/jump_label.h>
#include <linux/trace_events.h>

#include <asm/virtext.h>

#include "cpuid.h"
#include "ept.h"
#include "tdx.h"

#include <trace/events/kvm.h>
#include "trace.h"

#ifdef CONFIG_KVM_INTEL_TDX

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

#include "seam.c"

bool __read_mostly emulate_seam = 1;
module_param(emulate_seam, bool, 0444);

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
	kvm->arch.shadow_mmio_value = 0;

	if (emulate_seam)
		return seam_tdcreate(kvm);

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
	if (emulate_seam)
		return seam_tdcreatevp(vcpu);

	/*
	 * TODO:
	 * SEAMCALL(TDCREATEVP)
	 * SEAMCALL(TDADDVPX)
	 */
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

static void tdx_vcpu_run(struct kvm_vcpu *vcpu)
{
	if (emulate_seam) {
		seam_tdenter(vcpu);
		return;
	}

	/*
	 * TODO:
	 * SEAMCALL(TDENTER)
	 */
}

static void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
	u32 exit_reason = seamret_exit_reason(vcpu);

	if (exit_reason == EXIT_REASON_EXCEPTION_NMI)
		vmx_handle_exception_nmi_irqoff(vcpu,
			seamret_intr_info(vcpu));
	else if (exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT)
		vmx_handle_external_interrupt_irqoff(vcpu,
			seamret_exit_reason(vcpu));
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
	unsigned long exit_reason;
	int ret;

	if (tdvmcall_exit_type(vcpu)) {
		ret = tdx_emulate_vmcall(vcpu);
		return 1;
	}

	exit_reason = tdvmcall_exit_reason(vcpu);

	trace_kvm_tdvmcall(vmcs_readl(GUEST_RIP), exit_reason,
			   tdvmcall_p1_read(vcpu), tdvmcall_p2_read(vcpu),
			   tdvmcall_p3_read(vcpu), tdvmcall_p4_read(vcpu));

	switch (exit_reason) {
	case EXIT_REASON_TRIPLE_FAULT:
		ret = tdx_trace_tdvmcall(vcpu);
		break;
	case EXIT_REASON_CPUID:
		ret = tdx_emulate_cpuid(vcpu);
		break;
	case EXIT_REASON_HLT:
		ret = tdx_emulate_hlt(vcpu);
		break;
	// case EXIT_REASON_RDPMC:
	// 	ret = tdx_emulate_rdpmc(vcpu);
	// 	break;
	// case EXIT_REASON_VMCALL:
	// 	
	// 	break;
	case EXIT_REASON_IO_INSTRUCTION:
		ret = tdx_emulate_io(vcpu);
		break;
	case EXIT_REASON_MSR_READ:
		ret = tdx_emulate_rdmsr(vcpu);
		break;
	case EXIT_REASON_MSR_WRITE:
		ret = tdx_emulate_wrmsr(vcpu);
		break;
	case EXIT_REASON_EPT_VIOLATION:
		ret = tdx_emulate_mmio(vcpu);
		break;
	default:
		tdvmcall_set_return_code(vcpu, -EOPNOTSUPP);
		ret = 1;
		break;
	}

	return ret;
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

static int __init tdx_hardware_setup(void)
{
	if (emulate_seam)
		return seam_hardware_setup();

	return 0;
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
	return 0;
}

static void tdx_exit(void)
{

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
static void tdx_handle_exit_irqoff(struct kvm_vcpu *vcpu) {}
static int tdx_handle_exit(struct kvm_vcpu *vcpu,
			   enum exit_fastpath_completion fastpath) { return 0; }
static int tdx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info) { return 0; }
static bool tdx_is_emulatable(struct kvm_vcpu *vcpu, void *insn, int insn_len) { return false; }
static int __init tdx_check_processor_compatibility(void) { return 0; }
static int __init tdx_hardware_setup(void) { return 0; }
static void __init tdx_early_init(unsigned int *vcpu_size,
				  unsigned int *vcpu_align) {}
static int __init tdx_init(void) { return 0; }
static void tdx_exit(void) {}

#endif
