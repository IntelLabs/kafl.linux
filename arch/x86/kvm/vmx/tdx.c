// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/jump_label.h>
#include <linux/trace_events.h>
#include <linux/pagemap.h>
#include <linux/kvm_host.h>

#include <asm/virtext.h>

#include "trace.h"
#include "vmx.h"
#include "x86.h"
#include "lapic.h"
#include "tdx.h"
#include "../irq.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

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

static __always_inline unsigned long tdvmcall_exit_type(struct kvm_vcpu *vcpu)
{
	return kvm_r10_read(vcpu);
}
static __always_inline unsigned long tdvmcall_exit_reason(struct kvm_vcpu *vcpu)
{
	return kvm_r11_read(vcpu);
}
static __always_inline void tdvmcall_set_return_code(struct kvm_vcpu *vcpu, long val)
{
	kvm_r10_write(vcpu, val);
}

static __always_inline void tdvmcall_set_return_val(struct kvm_vcpu *vcpu,
						    unsigned long val)
{
	kvm_r11_write(vcpu, val);
}

static int tdx_emulate_hlt(struct kvm_vcpu *vcpu)
{
	WARN_ONCE(1,"TDX: %s\n", __func__);
	tdvmcall_set_return_code(vcpu, 0);

	kvm_vcpu_halt(to_kvm_vcpu(vcpu));
	return 0;
}

static int tdx_complete_pio_in(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
	unsigned long val = 0;
	int ret;

	WARN_ON_ONCE(vcpu->arch.pio.count != 1);

	ret = ctxt->ops->pio_in_emulated(ctxt, vcpu->arch.pio.size,
					 vcpu->arch.pio.port, &val, 1);
	WARN_ON(!ret);

	tdvmcall_set_return_code(vcpu, 0);
	tdvmcall_set_return_val(vcpu, val);

	return 1;
}

static int tdx_emulate_io(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;
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
//		trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val);
	}
	return 1;
}

static inline int tdx_mmio_write(struct kvm_vcpu *vcpu, gpa_t gpa, int size)
{
	unsigned long val = tdvmcall_p4_read(vcpu);

	if (kvm_iodevice_write(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    kvm_io_bus_write(vcpu, KVM_MMIO_BUS, gpa, size, &val))
		return -EOPNOTSUPP;

	/* trace_kvm_mmio(KVM_TRACE_MMIO_WRITE, size, gpa, &val); */
	return 0;
}

static inline int tdx_mmio_read(struct kvm_vcpu *vcpu, gpa_t gpa, int size)
{
	unsigned long val;

	if (kvm_iodevice_read(vcpu, &vcpu->arch.apic->dev, gpa, size, &val) &&
	    kvm_io_bus_read(vcpu, KVM_MMIO_BUS, gpa, size, &val))
		return -EOPNOTSUPP;

	tdvmcall_set_return_val(vcpu, val);
	/* trace_kvm_mmio(KVM_TRACE_MMIO_READ, size, gpa, &val); */
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
		/* trace_kvm_mmio(KVM_TRACE_MMIO_READ_UNSATISFIED, size, gpa, NULL); */
	}
	return 0;
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

static int tdx_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	WARN_ON(1);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
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

	//TODO
	/* trace_kvm_tdvmcall(vmcs_readl(GUEST_RIP), exit_reason, */
	/* 		   tdvmcall_p1_read(vcpu), tdvmcall_p2_read(vcpu), */
	/* 		   tdvmcall_p3_read(vcpu), tdvmcall_p4_read(vcpu)); */

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
	WARN_ONCE(1, "TDX: %s\n", __func__);
//TODO
#if 1
	kvm_vcpu_halt(vcpu);
#else
	if (halt_on_triple_fault)
		return kvm_vcpu_halt(vcpu);

	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	vcpu->mmio_needed = 0;
#endif
	return 0;
}

static int tdx_handle_ept_violation(struct kvm_vcpu *tdx_vcpu)
{
	unsigned long exit_qualification =  tdexit_exit_qual(tdx_vcpu);
	struct kvm_vcpu *vcpu = to_kvm_vcpu(tdx_vcpu);
	gpa_t gpa = tdexit_gpa(tdx_vcpu);
	u64 error_code;

	/* TODO: Use TDX's version of the vCPU to handle MMU stuff. */

	trace_kvm_page_fault(vcpu, gpa, exit_qualification);

	/* Is it a read fault? */
	error_code = (exit_qualification & EPT_VIOLATION_ACC_READ)
		     ? PFERR_USER_MASK : 0;
	/* Is it a write fault? */
	error_code |= (exit_qualification & EPT_VIOLATION_ACC_WRITE)
		      ? PFERR_WRITE_MASK : 0;
	/* Is it a fetch fault? */
	error_code |= (exit_qualification & EPT_VIOLATION_ACC_INSTR)
		      ? PFERR_FETCH_MASK : 0;
	/* ept page table entry is present? */
	error_code |= (exit_qualification & EPT_VIOLATION_RWX_MASK)
		      ? PFERR_PRESENT_MASK : 0;

	error_code |= (exit_qualification & 0x100) != 0 ?
	       PFERR_GUEST_FINAL_MASK : PFERR_GUEST_PAGE_MASK;

	vcpu->arch.exit_qualification = exit_qualification;
	return kvm_mmu_page_fault(vcpu, gpa, error_code, NULL, 0);
}

int __tdx_handle_exit(struct kvm_vcpu *vcpu)
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
	default:
		break;
	}

	kvm_pr_unimpl("unexpected exit reason 0x%x\n", exit_reason);
	return -EFAULT;
}
