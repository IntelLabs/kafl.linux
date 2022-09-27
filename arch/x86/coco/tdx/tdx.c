// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2022 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "tdx: " fmt

#include <linux/cpufeature.h>
#include <linux/pci.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/numa.h>
#include <linux/nmi.h>
#include <linux/random.h>
#include <linux/virtio_anchor.h>
#include <asm/coco.h>
#include <asm/tdx.h>
#include <asm/i8259.h>
#include <asm/vmx.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/pgtable.h>
#include <asm/irqdomain.h>
#include <uapi/asm/tdx.h>

#include "tdx.h"

#define CREATE_TRACE_POINTS
#include <asm/trace/tdx.h>

/* MMIO direction */
#define EPT_READ	0
#define EPT_WRITE	1

/* Port I/O direction */
#define PORT_READ	0
#define PORT_WRITE	1

/* See Exit Qualification for I/O Instructions in VMX documentation */
#define VE_IS_IO_IN(e)		((e) & BIT(3))
#define VE_GET_IO_SIZE(e)	(((e) & GENMASK(2, 0)) + 1)
#define VE_GET_PORT_NUM(e)	((e) >> 16)
#define VE_IS_IO_STRING(e)	((e) & BIT(4))

#define DRIVER_NAME	"tdx-guest"

/* TD Attributes masks */
#define        ATTR_DEBUG_MODE                 BIT(0)

/* Caches GPA width from TDG.VP.INFO TDCALL */
static unsigned int gpa_width;
/* Caches TD Attributes from TDG.VP.INFO TDCALL */
static u64 td_attr;

static struct miscdevice tdx_misc_dev;
int tdx_notify_irq = -1;

/* Traced version of __tdx_hypercall */
static u64 __trace_tdx_hypercall(struct tdx_hypercall_args *args,
		unsigned long flags)
{
	u64 err;

	//trace_tdx_hypercall_enter_rcuidle(args->r11, args->r12, args->r13,
	//		args->r14, args->r15);
	err = __tdx_hypercall(args, flags);
	//trace_tdx_hypercall_exit_rcuidle(err, args->r11, args->r12,
	//		args->r13, args->r14, args->r15);

	return err;
}

/* Traced version of __tdx_module_call */
static u64 __trace_tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8,
		u64 r9, struct tdx_module_output *out)
{
	struct tdx_module_output dummy_out;
	u64 err;

	if (!out)
		out = &dummy_out;

	trace_tdx_module_call_enter_rcuidle(fn, rcx, rdx, r8, r9);
	err = __tdx_module_call(fn, rcx, rdx, r8, r9, out);
	trace_tdx_module_call_exit_rcuidle(err, out->rcx, out->rdx,
			out->r8, out->r9, out->r10, out->r11);

	return err;
}

/*
 * Wrapper for standard use of __tdx_hypercall with no output aside from
 * return code.
 */
static inline u64 _trace_tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = fn,
		.r12 = r12,
		.r13 = r13,
		.r14 = r14,
		.r15 = r15,
	};

	return __trace_tdx_hypercall(&args, 0);
}

/* Called from __tdx_hypercall() for unrecoverable failure */
void __tdx_hypercall_failed(void)
{
	panic("TDVMCALL failed. TDX module bug?");
}

/*
 * The TDG.VP.VMCALL-Instruction-execution sub-functions are defined
 * independently from but are currently matched 1:1 with VMX EXIT_REASONs.
 * Reusing the KVM EXIT_REASON macros makes it easier to connect the host and
 * guest sides of these calls.
 */
static u64 hcall_func(u64 exit_reason)
{
	return exit_reason;
}

#ifdef CONFIG_KVM_GUEST
long tdx_kvm_hypercall(unsigned int nr, unsigned long p1, unsigned long p2,
		       unsigned long p3, unsigned long p4)
{
	struct tdx_hypercall_args args = {
		.r10 = nr,
		.r11 = p1,
		.r12 = p2,
		.r13 = p3,
		.r14 = p4,
	};

	return __trace_tdx_hypercall(&args, 0);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall);
#endif

/*
 * Used for TDX guests to make calls directly to the TD module.  This
 * should only be used for calls that have no legitimate reason to fail
 * or where the kernel can not survive the call failing.
 */
static inline void tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
				   struct tdx_module_output *out)
{
	if (__trace_tdx_module_call(fn, rcx, rdx, r8, r9, out))
		panic("TDCALL %lld failed (Buggy TDX module!)\n", fn);
}

/*
 * tdx_hcall_set_notify_intr() - Setup Event Notify Interrupt Vector.
 *
 * @vector: Vector address to be used for notification.
 *
 * return 0 on success or failure error number.
 */
static long tdx_hcall_set_notify_intr(u8 vector)
{
	/* Minimum vector value allowed is 32 */
	if (vector < 32)
		return -EINVAL;

	/*
	 * Register callback vector address with VMM. More details
	 * about the ABI can be found in TDX Guest-Host-Communication
	 * Interface (GHCI), sec titled
	 * "TDG.VP.VMCALL<SetupEventNotifyInterrupt>".
	 */
	if (_trace_tdx_hypercall(TDVMCALL_SETUP_NOTIFY_INTR, vector, 0, 0, 0))
		return -EIO;

	return 0;
}

static void tdx_parse_tdinfo(void)
{
	struct tdx_module_output out;

	/*
	 * TDINFO TDX module call is used to get the TD execution environment
	 * information like GPA width, number of available vcpus, debug mode
	 * information, TD attributes etc. More details about the ABI can be
	 * found in TDX Guest-Host-Communication Interface (GHCI), section
	 * 2.4.2 TDCALL [TDG.VP.INFO].
	 *
	 * The GPA width that comes out of this call is critical. TDX guests
	 * can not meaningfully run without it.
	 */
	tdx_module_call(TDX_GET_INFO, 0, 0, 0, 0, &out);

	gpa_width = out.rcx & GENMASK(5, 0);

	td_attr = out.rdx;
}

static u64 get_cc_mask(void)
{
	/*
	 * The highest bit of a guest physical address is the "sharing" bit.
	 * Set it for shared pages and clear it for private pages.
	 */
	return BIT_ULL(gpa_width - 1);
}

/*
 * The TDX module spec states that #VE may be injected for a limited set of
 * reasons:
 *
 *  - Emulation of the architectural #VE injection on EPT violation;
 *
 *  - As a result of guest TD execution of a disallowed instruction,
 *    a disallowed MSR access, or CPUID virtualization;
 *
 *  - A notification to the guest TD about anomalous behavior;
 *
 * The last one is opt-in and is not used by the kernel.
 *
 * The Intel Software Developer's Manual describes cases when instruction
 * length field can be used in section "Information for VM Exits Due to
 * Instruction Execution".
 *
 * For TDX, it ultimately means GET_VEINFO provides reliable instruction length
 * information if #VE occurred due to instruction execution, but not for EPT
 * violations.
 */
static int ve_instr_len(struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_MSR_WRITE:
	case EXIT_REASON_CPUID:
	case EXIT_REASON_IO_INSTRUCTION:
		/* It is safe to use ve->instr_len for #VE due instructions */
		return ve->instr_len;
	case EXIT_REASON_EPT_VIOLATION:
		/*
		 * For EPT violations, ve->insn_len is not defined. For those,
		 * the kernel must decode instructions manually and should not
		 * be using this function.
		 */
		WARN_ONCE(1, "ve->instr_len is not defined for EPT violations");
		return 0;
	default:
		WARN_ONCE(1, "Unexpected #VE-type: %lld\n", ve->exit_reason);
		return ve->instr_len;
	}
}

static bool is_td_attr_set(u64 mask)
{
	return !!(td_attr & mask);
}

bool tdx_debug_enabled(void)
{
	return is_td_attr_set(ATTR_DEBUG_MODE);
}

static u64 __cpuidle __halt(const bool irq_disabled, const bool do_sti)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_HLT),
		.r12 = irq_disabled,
	};

	/*
	 * Emulate HLT operation via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section 3.8 TDG.VP.VMCALL<Instruction.HLT>.
	 *
	 * The VMM uses the "IRQ disabled" param to understand IRQ
	 * enabled status (RFLAGS.IF) of the TD guest and to determine
	 * whether or not it should schedule the halted vCPU if an
	 * IRQ becomes pending. E.g. if IRQs are disabled, the VMM
	 * can keep the vCPU in virtual HLT, even if an IRQ is
	 * pending, without hanging/breaking the guest.
	 */
	return __trace_tdx_hypercall(&args, do_sti ? TDX_HCALL_ISSUE_STI : 0);
}

static int handle_halt(struct ve_info *ve)
{
	/*
	 * Since non safe halt is mainly used in CPU offlining
	 * and the guest will always stay in the halt state, don't
	 * call the STI instruction (set do_sti as false).
	 */
	const bool irq_disabled = irqs_disabled();
	const bool do_sti = false;

	if (__halt(irq_disabled, do_sti))
		return -EIO;

	return ve_instr_len(ve);
}

void __cpuidle tdx_safe_halt(void)
{
	 /*
	  * For do_sti=true case, __tdx_hypercall() function enables
	  * interrupts using the STI instruction before the TDCALL. So
	  * set irq_disabled as false.
	  */
	const bool irq_disabled = false;
	const bool do_sti = true;

#ifdef CONFIG_TDX_FUZZ_KAFL
	// don't wait for guest to time out
	kafl_fuzz_event(KAFL_SAFE_HALT);
#endif

	/*
	 * Use WARN_ONCE() to report the failure.
	 */
	if (__halt(irq_disabled, do_sti))
		WARN_ONCE(1, "HLT instruction emulation failed\n");
}

static u64 _tdx_fuzz_msr_filtered(unsigned int msr, u64 orig)
{
       /* MSRs managed by HW - should not get these via #VE */
       switch (msr) {
               case MSR_EFER:
               case MSR_IA32_CR_PAT:
               case MSR_FS_BASE:
               case MSR_GS_BASE:
               case MSR_KERNEL_GS_BASE:
               case MSR_IA32_SYSENTER_CS:
               case MSR_IA32_SYSENTER_EIP:
               case MSR_IA32_SYSENTER_ESP:
               case MSR_STAR:
               case MSR_LSTAR:
               case MSR_SYSCALL_MASK:
               case MSR_IA32_XSS:
               case MSR_TSC_AUX:
               case MSR_IA32_SPEC_CTRL:
               case MSR_IA32_PRED_CMD:
               case MSR_IA32_FLUSH_CMD:
               case MSR_IA32_DS_AREA:
                       BUG();
       }

       /* MSR exceptions - skip fuzzing MSRs that are debug-only
        * or where HW injects an error - modulated by asm/msr-list.h */
       switch (msr) {
               case MSR_IA32_SMM_MONITOR_CTL:
               case MSR_IA32_SMBASE:
               case MSR_IA32_VMX_BASIC:
               case MSR_IA32_VMX_PINBASED_CTLS:
               case MSR_IA32_VMX_PROCBASED_CTLS:
               case MSR_IA32_VMX_EXIT_CTLS:
               case MSR_IA32_VMX_ENTRY_CTLS:
               case MSR_IA32_VMX_MISC:
               case MSR_IA32_VMX_CR0_FIXED0:
               case MSR_IA32_VMX_CR0_FIXED1:
               case MSR_IA32_VMX_CR4_FIXED0:
               case MSR_IA32_VMX_CR4_FIXED1:
               case MSR_IA32_VMX_VMCS_ENUM:
               case MSR_IA32_VMX_PROCBASED_CTLS2:
               case MSR_IA32_VMX_EPT_VPID_CAP:
               case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
               case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
               case MSR_IA32_VMX_TRUE_EXIT_CTLS:
               case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
               case MSR_IA32_VMX_VMFUNC:
               case MSR_IA32_BNDCFGS:
               case MSR_IA32_PASID:
               // HW injects #GP
                       return orig;

               case MSR_IA32_PERFCTR0:
               case MSR_IA32_PERFCTR1:
               case MSR_IA32_PERF_CAPABILITIES:
               case MSR_CORE_PERF_FIXED_CTR0:
               case MSR_CORE_PERF_FIXED_CTR1:
               case MSR_CORE_PERF_FIXED_CTR2:
               case MSR_CORE_PERF_FIXED_CTR3:
               case MSR_CORE_PERF_FIXED_CTR_CTRL:
               case MSR_CORE_PERF_GLOBAL_STATUS:
               case MSR_CORE_PERF_GLOBAL_CTRL:
               case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
               case MSR_PERF_METRICS:
               	       // HW injects #GP unless PERFMON=1
               	       return orig;

               case MSR_IA32_RTIT_STATUS:
               case MSR_IA32_RTIT_ADDR0_A:
               case MSR_IA32_RTIT_ADDR0_B:
               case MSR_IA32_RTIT_ADDR1_A:
               case MSR_IA32_RTIT_ADDR1_B:
               case MSR_IA32_RTIT_ADDR2_A:
               case MSR_IA32_RTIT_ADDR2_B:
               case MSR_IA32_RTIT_ADDR3_A:
               case MSR_IA32_RTIT_ADDR3_B:
               case MSR_IA32_RTIT_CR3_MATCH:
               case MSR_IA32_RTIT_OUTPUT_BASE:
               case MSR_IA32_RTIT_OUTPUT_MASK:
                       // HW injects #GP unless XFAM[8]=1
                       return orig;

               case MSR_ARCH_LBR_INFO_0 ... MSR_ARCH_LBR_TO_0+0xff:
                       // HW injects #GP unless XFAM[15]=1
                       return orig;

               case MSR_IA32_PMC0:
               case MSR_IA32_PMC0+1:
               case MSR_IA32_PMC0+2:
               case MSR_IA32_PMC0+3:
               case MSR_IA32_PMC0+4:
               case MSR_IA32_PMC0+5:
               case MSR_IA32_PMC0+6:
               case MSR_IA32_PMC0+7:
                       // HW injects #GP unless PERFMON=1
                       return orig;
               case MSR_IA32_APICBASE:
                       // HW ensures x2apic is enabled
                       orig = tdx_fuzz(orig, msr, 8, TDX_FUZZ_MSR_READ);
                       return orig     | X2APIC_ENABLE;
               //case MSR_IA32_UMWAIT_CONTROL:
               // HW inject #GP unless... CPUID(7,0).ECX[5]??
       }
       return tdx_fuzz(orig, msr, 8, TDX_FUZZ_MSR_READ);
}


static int read_msr(struct pt_regs *regs, struct ve_info *ve)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_MSR_READ),
		.r12 = regs->cx,
	};
	u64 ret;

	/*
	 * Emulate the MSR read via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "TDG.VP.VMCALL<Instruction.RDMSR>".
	 */
	ret = __trace_tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT);
	if (ret || tdx_fuzz_err(TDX_FUZZ_MSR_READ_ERR))
		return -EIO;

	/* filter the MSRs to only fuzz host controlled */
	args.r11 = _tdx_fuzz_msr_filtered(regs->cx, args.r11);
	regs->ax = lower_32_bits(args.r11);
	regs->dx = upper_32_bits(args.r11);
	return ve_instr_len(ve);
}

static int write_msr(struct pt_regs *regs, struct ve_info *ve)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_MSR_WRITE),
		.r12 = regs->cx,
		.r13 = (u64)regs->dx << 32 | regs->ax,
	};
	u64 ret;

	/*
	 * Emulate the MSR write via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) section titled "TDG.VP.VMCALL<Instruction.WRMSR>".
	 */
	ret = __trace_tdx_hypercall(&args, 0);
	if (ret || tdx_fuzz_err(TDX_FUZZ_MSR_WRITE_ERR))
		return -EIO;

	return ve_instr_len(ve);
}

/*
 * TDX has context switched MSRs and emulated MSRs. The emulated MSRs
 * normally trigger a #VE, but that is expensive, which can be avoided
 * by doing a direct TDCALL. Unfortunately, this cannot be done for all
 * because some MSRs are "context switched" and need WRMSR.
 *
 * The list for this is unfortunately quite long. To avoid maintaining
 * very long switch statements just do a fast path for the few critical
 * MSRs that need TDCALL, currently only TSC_DEADLINE.
 *
 * More can be added as needed.
 *
 * The others will be handled by the #VE handler as needed.
 * See 18.1 "MSR virtualization" in the TDX Module EAS
 */
static bool tdx_fast_tdcall_path_msr(unsigned int msr)
{
	switch (msr) {
	case MSR_IA32_TSC_DEADLINE:
		return true;
	default:
		return false;

	}
}

void notrace tdx_write_msr(unsigned int msr, u32 low, u32 high)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_MSR_WRITE),
		.r12 = msr,
		.r13 = (u64)high << 32 | low,
	};

	if (tdx_fast_tdcall_path_msr(msr))
		__tdx_hypercall(&args, 0);
	else
		native_write_msr(msr, low, high);
}

static int handle_cpuid(struct pt_regs *regs, struct ve_info *ve)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_CPUID),
		.r12 = regs->ax,
		.r13 = regs->cx,
	};

	/*
	 * Only allow VMM to control range reserved for hypervisor
	 * communication.
	 *
	 * Return all-zeros for any CPUID outside the range. It matches CPU
	 * behaviour for non-supported leaf.
	 */
	if (regs->ax < 0x40000000 || regs->ax > 0x4FFFFFFF) {
		regs->ax = regs->bx = regs->cx = regs->dx = 0;
		return ve_instr_len(ve);
	}

	/*
	 * Emulate the CPUID instruction via a hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "VP.VMCALL<Instruction.CPUID>".
	 */
	if (__trace_tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return -EIO;

	/*
	 * As per TDX GHCI CPUID ABI, r12-r15 registers contain contents of
	 * EAX, EBX, ECX, EDX registers after the CPUID instruction execution.
	 * So copy the register contents back to pt_regs.
	 */
	regs->ax = tdx_fuzz(args.r12, -1, 2, TDX_FUZZ_CPUID1);
	regs->bx = tdx_fuzz(args.r13, -1, 2, TDX_FUZZ_CPUID2);
	regs->cx = tdx_fuzz(args.r14, -1, 2, TDX_FUZZ_CPUID3);
	regs->dx = tdx_fuzz(args.r15, -1, 2, TDX_FUZZ_CPUID4);

	return ve_instr_len(ve);
}

static bool mmio_read(int size, unsigned long addr, unsigned long *val)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_EPT_VIOLATION),
		.r12 = size,
		.r13 = EPT_READ,
		.r14 = addr,
		.r15 = *val,
	};

	if (__trace_tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return false;
	*val = tdx_fuzz(args.r11, addr, size, TDX_FUZZ_MMIO_READ);
	return true;
}

static bool mmio_write(int size, unsigned long addr, unsigned long val)
{
	return !_trace_tdx_hypercall(hcall_func(EXIT_REASON_EPT_VIOLATION), size,
			EPT_WRITE, addr, val);
}

static int handle_mmio(struct pt_regs *regs, struct ve_info *ve)
{
	unsigned long *reg, val, vaddr;
	char buffer[MAX_INSN_SIZE];
	struct insn insn = {};
	enum mmio_type mmio;
	int size, extend_size;
	u8 extend_val = 0;

	/* Only in-kernel MMIO is supported */
	if (WARN_ON_ONCE(user_mode(regs)))
		return -EFAULT;

	if (copy_from_kernel_nofault(buffer, (void *)regs->ip, MAX_INSN_SIZE))
		return -EFAULT;

	if (insn_decode(&insn, buffer, MAX_INSN_SIZE, INSN_MODE_64))
		return -EINVAL;

	mmio = insn_decode_mmio(&insn, &size);
	if (WARN_ON_ONCE(mmio == MMIO_DECODE_FAILED))
		return -EINVAL;

	if (mmio != MMIO_WRITE_IMM && mmio != MMIO_MOVS) {
		reg = insn_get_modrm_reg_ptr(&insn, regs);
		if (!reg)
			return -EINVAL;
	}

	/*
	 * Reject EPT violation #VEs that split pages.
	 *
	 * MMIO accesses are supposed to be naturally aligned and therefore
	 * never cross page boundaries. Seeing split page accesses indicates
	 * a bug or a load_unaligned_zeropad() that stepped into an MMIO page.
	 *
	 * load_unaligned_zeropad() will recover using exception fixups.
	 */
	vaddr = (unsigned long)insn_get_addr_ref(&insn, regs);
	if (vaddr / PAGE_SIZE != (vaddr + size - 1) / PAGE_SIZE)
		return -EFAULT;

	/* Handle writes first */
	switch (mmio) {
	case MMIO_WRITE:
		memcpy(&val, reg, size);
		if (!mmio_write(size, ve->gpa, val))
			return -EIO;
		return insn.length;
	case MMIO_WRITE_IMM:
		val = insn.immediate.value;
		if (!mmio_write(size, ve->gpa, val))
			return -EIO;
		return insn.length;
	case MMIO_READ:
	case MMIO_READ_ZERO_EXTEND:
	case MMIO_READ_SIGN_EXTEND:
		/* Reads are handled below */
		break;
	case MMIO_MOVS:
	case MMIO_DECODE_FAILED:
		/*
		 * MMIO was accessed with an instruction that could not be
		 * decoded or handled properly. It was likely not using io.h
		 * helpers or accessed MMIO accidentally.
		 */
		return -EINVAL;
	default:
		WARN_ONCE(1, "Unknown insn_decode_mmio() decode value?");
		return -EINVAL;
	}

	/* Handle reads */
	if (!mmio_read(size, ve->gpa, &val))
		return -EIO;

	switch (mmio) {
	case MMIO_READ:
		/* Zero-extend for 32-bit operation */
		extend_size = size == 4 ? sizeof(*reg) : 0;
		break;
	case MMIO_READ_ZERO_EXTEND:
		/* Zero extend based on operand size */
		extend_size = insn.opnd_bytes;
		break;
	case MMIO_READ_SIGN_EXTEND:
		/* Sign extend based on operand size */
		extend_size = insn.opnd_bytes;
		if (size == 1 && val & BIT(7))
			extend_val = 0xFF;
		else if (size > 1 && val & BIT(15))
			extend_val = 0xFF;
		break;
	default:
		/* All other cases has to be covered with the first switch() */
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	if (extend_size)
		memset(reg, extend_val, extend_size);
	memcpy(reg, &val, size);
	return insn.length;
}

static unsigned long tdx_virt_mmio(int size, bool write, unsigned long vaddr,
	unsigned long* val)
{
	pte_t* pte;
	int level;

	pte = lookup_address(vaddr, &level);
	if (!pte)
		return -EIO;

	return write ? 
		mmio_write(size,
			(pte_pfn(*pte) << PAGE_SHIFT) +
			(vaddr & ~page_level_mask(level)),
			*val) :
		mmio_read(size,
			(pte_pfn(*pte) << PAGE_SHIFT) +
			(vaddr & ~page_level_mask(level)),
			val);
}

static unsigned char tdx_mmio_readb(void __iomem* addr)
{
	unsigned long val;

	if (tdx_virt_mmio(1, false, (unsigned long)addr, &val))
		return 0xff;
	return val;
}

static unsigned short tdx_mmio_readw(void __iomem* addr)
{
	unsigned long val;

	if (tdx_virt_mmio(2, false, (unsigned long)addr, &val))
		return 0xffff;
	return val;
}

static unsigned int tdx_mmio_readl(void __iomem* addr)
{
	unsigned long val;

	if (tdx_virt_mmio(4, false, (unsigned long)addr, &val))
		return 0xffffffff;
	return val;
}

unsigned long tdx_mmio_readq(void __iomem* addr)
{
	unsigned long val;

	if (tdx_virt_mmio(8, false, (unsigned long)addr, &val))
		return 0xffffffffffffffff;
	return val;
}

static void tdx_mmio_writeb(unsigned char v, void __iomem* addr)
{
	unsigned long val = v;

	tdx_virt_mmio(1, true, (unsigned long)addr, &val);
}

static void tdx_mmio_writew(unsigned short v, void __iomem* addr)
{
	unsigned long val = v;

	tdx_virt_mmio(2, true, (unsigned long)addr, &val);
}

static void tdx_mmio_writel(unsigned int v, void __iomem* addr)
{
	unsigned long val = v;

	tdx_virt_mmio(4, true, (unsigned long)addr, &val);
}

static void tdx_mmio_writeq(unsigned long v, void __iomem* addr)
{
	unsigned long val = v;

	tdx_virt_mmio(8, true, (unsigned long)addr, &val);
}

static const struct iomap_mmio tdx_iomap_mmio = {
	.ireadb = tdx_mmio_readb,
	.ireadw = tdx_mmio_readw,
	.ireadl = tdx_mmio_readl,
	.ireadq = tdx_mmio_readq,
	.iwriteb = tdx_mmio_writeb,
	.iwritew = tdx_mmio_writew,
	.iwritel = tdx_mmio_writel,
	.iwriteq = tdx_mmio_writeq,
};

static bool handle_in(struct pt_regs *regs, int size, int port)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_IO_INSTRUCTION),
		.r12 = size,
		.r13 = PORT_READ,
		.r14 = port,
	};
	u64 mask = GENMASK(BITS_PER_BYTE * size, 0);
	bool success;

	if (!tdx_allowed_port(port)) {
		regs->ax &= ~mask;
		regs->ax |= (UINT_MAX & mask);
		return true;
	}

	/*
	 * Emulate the I/O read via hypercall. More info about ABI can be found
	 * in TDX Guest-Host-Communication Interface (GHCI) section titled
	 * "TDG.VP.VMCALL<Instruction.IO>".
	 */
	success = !__trace_tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT) &&
		  !tdx_fuzz_err(TDX_FUZZ_PORT_IN_ERR);

	/* Update part of the register affected by the emulated instruction */
	regs->ax &= ~mask;
	if (success)
		regs->ax |= tdx_fuzz(args.r11, port, size, TDX_FUZZ_PORT_IN) & mask;

	return success;
}

static bool handle_out(struct pt_regs *regs, int size, int port)
{
	u64 mask = GENMASK(BITS_PER_BYTE * size, 0);

	if (!tdx_allowed_port(port))
		return true;

	/*
	 * Emulate the I/O write via hypercall. More info about ABI can be found
	 * in TDX Guest-Host-Communication Interface (GHCI) section titled
	 * "TDG.VP.VMCALL<Instruction.IO>".
	 */
	return !_tdx_hypercall(hcall_func(EXIT_REASON_IO_INSTRUCTION), size,
			       PORT_WRITE, port, regs->ax & mask);
}

/*
 * Emulate I/O using hypercall.
 *
 * Assumes the IO instruction was using ax, which is enforced
 * by the standard io.h macros.
 *
 * Return True on success or False on failure.
 */
static int handle_io(struct pt_regs *regs, struct ve_info *ve)
{
	u32 exit_qual = ve->exit_qual;
	int size, port;
	bool in, ret;

	if (VE_IS_IO_STRING(exit_qual))
		return -EIO;

	in   = VE_IS_IO_IN(exit_qual);
	size = VE_GET_IO_SIZE(exit_qual);
	port = VE_GET_PORT_NUM(exit_qual);

	if (in)
		ret = handle_in(regs, size, port);
	else
		ret = handle_out(regs, size, port);
	if (!ret)
		return -EIO;

	return ve_instr_len(ve);
}

/*
 * Early #VE exception handler. Only handles a subset of port I/O.
 * Intended only for earlyprintk. If failed, return false.
 */
__init bool tdx_early_handle_ve(struct pt_regs *regs)
{
	struct ve_info ve;
	int insn_len;

	tdx_get_ve_info(&ve);

	if (ve.exit_reason != EXIT_REASON_IO_INSTRUCTION)
		return false;

	insn_len = handle_io(regs, &ve);
	if (insn_len < 0)
		return false;

	regs->ip += insn_len;
	return true;
}

void tdx_get_ve_info(struct ve_info *ve)
{
	struct tdx_module_output out;

	/*
	 * Called during #VE handling to retrieve the #VE info from the
	 * TDX module.
	 *
	 * This has to be called early in #VE handling.  A "nested" #VE which
	 * occurs before this will raise a #DF and is not recoverable.
	 *
	 * The call retrieves the #VE info from the TDX module, which also
	 * clears the "#VE valid" flag. This must be done before anything else
	 * because any #VE that occurs while the valid flag is set will lead to
	 * #DF.
	 *
	 * Note, the TDX module treats virtual NMIs as inhibited if the #VE
	 * valid flag is set. It means that NMI=>#VE will not result in a #DF.
	 */
	tdx_module_call(TDX_GET_VEINFO, 0, 0, 0, 0, &out);

	/* Transfer the output parameters */
	ve->exit_reason = out.rcx;
	ve->exit_qual   = out.rdx;
	ve->gla         = out.r8;
	ve->gpa         = out.r9;
	ve->instr_len   = lower_32_bits(out.r10);
	ve->instr_info  = upper_32_bits(out.r10);
}

/*
 * Handle the user initiated #VE.
 *
 * On success, returns the number of bytes RIP should be incremented (>=0)
 * or -errno on error.
 */
static int virt_exception_user(struct pt_regs *regs, struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_CPUID:
		return handle_cpuid(regs, ve);
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return -EIO;
	}
}

/*
 * Handle the kernel #VE.
 *
 * On success, returns the number of bytes RIP should be incremented (>=0)
 * or -errno on error.
 */
static int virt_exception_kernel(struct pt_regs *regs, struct ve_info *ve)
{

	trace_tdx_virtualization_exception_rcuidle(regs->ip, ve->exit_reason,
			ve->exit_qual, ve->gpa, ve->instr_len, ve->instr_info,
			regs->cx, regs->ax, regs->dx);

	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		return handle_halt(ve);
	case EXIT_REASON_MSR_READ:
		return read_msr(regs, ve);
	case EXIT_REASON_MSR_WRITE:
		return write_msr(regs, ve);
	case EXIT_REASON_CPUID:
		return handle_cpuid(regs, ve);
	case EXIT_REASON_EPT_VIOLATION:
		return handle_mmio(regs, ve);
	case EXIT_REASON_IO_INSTRUCTION:
		return handle_io(regs, ve);
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return -EIO;
	}
}

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve)
{
	int insn_len;

	if (user_mode(regs))
		insn_len = virt_exception_user(regs, ve);
	else
		insn_len = virt_exception_kernel(regs, ve);
	if (insn_len < 0)
		return false;

	/* After successful #VE handling, move the IP */
	regs->ip += insn_len;

	/*
	 * Single-stepping through an emulated instruction is
	 * two-fold: handling the #VE and raising a #DB. The
	 * former is taken care of above; this tells the #VE
	 * trap handler to do the latter. #DB is raised after
	 * the instruction has been executed; the IP also needs
	 * to be advanced in this case.
	 */
	if (regs->flags & X86_EFLAGS_TF)
		return false;

	return true;
}

static bool tdx_tlb_flush_required(bool private)
{
	/*
	 * TDX guest is responsible for flushing TLB on private->shared
	 * transition. VMM is responsible for flushing on shared->private.
	 *
	 * The VMM _can't_ flush private addresses as it can't generate PAs
	 * with the guest's HKID.  Shared memory isn't subject to integrity
	 * checking, i.e. the VMM doesn't need to flush for its own protection.
	 *
	 * There's no need to flush when converting from shared to private,
	 * as flushing is the VMM's responsibility in this case, e.g. it must
	 * flush to avoid integrity failures in the face of a buggy or
	 * malicious guest.
	 */
	return !private;
}

static bool tdx_cache_flush_required(void)
{
	/*
	 * AMD SME/SEV can avoid cache flushing if HW enforces cache coherence.
	 * TDX doesn't have such capability.
	 *
	 * Flush cache unconditionally.
	 */
	return true;
}

static unsigned long try_accept_one(phys_addr_t start, unsigned long len,
				    enum pg_level pg_level)
{
	unsigned long accept_size = page_level_size(pg_level);
	u64 tdcall_rcx;
	u8 page_size;

	if (!IS_ALIGNED(start, accept_size))
		return 0;

	if (len < accept_size)
		return 0;

	/*
	 * Pass the page physical address to the TDX module to accept the
	 * pending, private page.
	 *
	 * Bits 2:0 of RCX encode page size: 0 - 4K, 1 - 2M, 2 - 1G.
	 */
	switch (pg_level) {
	case PG_LEVEL_4K:
		page_size = 0;
		break;
	case PG_LEVEL_2M:
		page_size = 1;
		break;
	case PG_LEVEL_1G:
		page_size = 2;
		break;
	default:
		return 0;
	}

	tdcall_rcx = start | page_size;
	if (__trace_tdx_module_call(TDX_ACCEPT_PAGE, tdcall_rcx, 0, 0,
				0, NULL))
		return 0;

	return accept_size;
}

static bool tdx_enc_status_changed_phys(phys_addr_t start, phys_addr_t end,
					bool enc)
{
	u64 ret;

	if (!enc) {
		/* Set the shared (decrypted) bits: */
		start |= cc_mkdec(0);
		end   |= cc_mkdec(0);
	}

	/*
	 * Notify the VMM about page mapping conversion. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface (GHCI),
	 * section "TDG.VP.VMCALL<MapGPA>"
	 */
	ret = _trace_tdx_hypercall(TDVMCALL_MAP_GPA, start, end - start, 0, 0);
	if (ret || tdx_fuzz_err(TDX_FUZZ_MAP_ERR))
		return false;

	/* private->shared conversion  requires only MapGPA call */
	if (!enc)
		return true;

	/*
	 * For shared->private conversion, accept the page using
	 * TDX_ACCEPT_PAGE TDX module call.
	 */
	while (start < end) {
		unsigned long len = end - start;
		unsigned long accept_size;

		/*
		 * Try larger accepts first. It gives chance to VMM to keep
		 * 1G/2M Secure EPT entries where possible and speeds up
		 * process by cutting number of hypercalls (if successful).
		 */

		accept_size = try_accept_one(start, len, PG_LEVEL_1G);
		if (!accept_size)
			accept_size = try_accept_one(start, len, PG_LEVEL_2M);
		if (!accept_size)
			accept_size = try_accept_one(start, len, PG_LEVEL_4K);
		if (!accept_size)
			return false;
		start += accept_size;
	}

	return true;
}

void tdx_accept_memory(phys_addr_t start, phys_addr_t end)
{
	if (!tdx_enc_status_changed_phys(start, end, true))
		panic("Accepting memory failed: %#llx-%#llx\n",  start, end);
}

/*
 * Inform the VMM of the guest's intent for this physical page: shared with
 * the VMM or private to the guest.  The VMM is expected to change its mapping
 * of the page in response.
 */
static bool tdx_enc_status_changed(unsigned long vaddr, int numpages, bool enc)
{
	phys_addr_t start = __pa(vaddr);
	phys_addr_t end = __pa(vaddr + numpages * PAGE_SIZE);

	return tdx_enc_status_changed_phys(start, end, enc);
}

void __init tdx_early_init(void)
{
	u64 cc_mask;
	u32 eax, sig[3];

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp(TDX_IDENT, sig, sizeof(sig)))
		return;

	/*
	 * Initializes gpa_width and td_attr. Must be called
	 * before is_td_attr_set() or get_cc_mask().
	 */
	tdx_parse_tdinfo();

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);
	setup_clear_cpu_cap(X86_FEATURE_MCE);
	setup_clear_cpu_cap(X86_FEATURE_MTRR);
	setup_clear_cpu_cap(X86_FEATURE_APERFMPERF);
	setup_clear_cpu_cap(X86_FEATURE_TME);
	setup_clear_cpu_cap(X86_FEATURE_CQM_LLC);
	setup_clear_cpu_cap(X86_FEATURE_MBA);

	/*
	 * The only secure (monotonous) timer inside a TD guest
	 * is the TSC. The TDX module does various checks on the TSC.
	 * There are no other reliable fall back options. Also checking
	 * against jiffies is very unreliable. So force the TSC reliable.
	 */
	setup_force_cpu_cap(X86_FEATURE_TSC_RELIABLE);

	/*
	 * In TDX relying on environmental noise like interrupt
	 * timing alone is dubious, because it can be directly
	 * controlled by a untrusted hypervisor. Make sure to
	 * mix in the CPU hardware random number generator too.
	 */
	random_enable_trust_cpu();

	iomap_mmio = &tdx_iomap_mmio;

	/*
	 * Make sure there is a panic if something goes wrong,
	 * just in case it's some kind of host attack.
	 */
	panic_on_oops = 1;

	/* Set restricted memory access for virtio. */
	virtio_set_mem_acc_cb(virtio_require_restricted_mem_acc);

	pv_ops.cpu.write_msr = tdx_write_msr;

	cc_set_vendor(CC_VENDOR_INTEL);
	cc_mask = get_cc_mask();
	cc_set_mask(cc_mask);

	/*
	 * All bits above GPA width are reserved and kernel treats shared bit
	 * as flag, not as part of physical address.
	 *
	 * Adjust physical mask to only cover valid GPA bits.
	 */
	physical_mask &= cc_mask - 1;

	x86_platform.guest.enc_cache_flush_required = tdx_cache_flush_required;
	x86_platform.guest.enc_tlb_flush_required   = tdx_tlb_flush_required;
	x86_platform.guest.enc_status_change_finish = tdx_enc_status_changed;

	legacy_pic = &null_legacy_pic;

	/*
	 * Disable NMI watchdog because of the risk of false positives
	 * and also can increase overhead in the TDX module.
	 * This is already done for KVM, but covers other hypervisors
	 * here.
	 */
	hardlockup_detector_disable();

	pci_disable_early();
	pci_disable_mmconf();

	pr_info("Guest detected\n");
}

static long tdx_get_report(void __user *argp)
{
	u8 *reportdata = NULL, *tdreport = NULL;
	struct tdx_report_req req;
	long ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	/*
	 * Per TDX Module 1.0 specification, section titled
	 * "TDG.MR.REPORT", REPORTDATA length is fixed as
	 * TDX_REPORTDATA_LEN, TDREPORT length is fixed as
	 * TDX_REPORTDATA_LEN, and TDREPORT subtype is fixed
	 * as 0. Also check for valid user pointers.
	 */
	if (!req.reportdata || !req.tdreport ||
	    req.subtype || req.rpd_len != TDX_REPORTDATA_LEN ||
	    req.tdr_len != TDX_REPORT_LEN)
		return -EINVAL;

	reportdata = kzalloc(req.rpd_len, GFP_KERNEL);
	if (!reportdata) {
		ret = -ENOMEM;
		goto out;
	}

	tdreport = kzalloc(req.tdr_len, GFP_KERNEL);
	if (!tdreport) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(reportdata, u64_to_user_ptr(req.reportdata),
			   req.rpd_len)) {
		ret = -EFAULT;
		goto out;
	}

	/*
	 * Generate TDREPORT using "TDG.MR.REPORT" TDCALL.
	 *
	 * Get the TDREPORT using REPORTDATA as input. Refer to
	 * section 22.3.3 TDG.MR.REPORT leaf in the TDX Module 1.0
	 * Specification for detailed information.
	 */
	ret = __tdx_module_call(TDX_GET_REPORT, virt_to_phys(tdreport),
				virt_to_phys(reportdata), req.subtype,
				0, NULL);
	if (ret) {
		ret = -EIO;
		goto out;
	}

	if (copy_to_user(u64_to_user_ptr(req.tdreport), tdreport, req.tdr_len))
		ret = -EFAULT;

out:
	kfree(reportdata);
	kfree(tdreport);
	return ret;
}

static long tdx_verifyreport(void __user *argp)
{
	struct tdx_verifyreport_req req;
	void *reportmac = NULL;
	long ret;

	/* Copy verifyrequest struct from the user buffer */
	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	/*
	 * Per TDX Module 1.5 specification, section titled
	 * "TDG.MR.VERIFYREPORT", REPORTMACSTRUCT length is
	 * fixed as TDX_REPORTMACSTRUCT_LEN.
	 */
	if (req.rpm_len != TDX_REPORTMACSTRUCT_LEN)
		return -EINVAL;

	/* Allocate buffer space for REPORTMACSTRUCT */
	reportmac = kmalloc(req.rpm_len, GFP_KERNEL);
	if (!reportmac)
		return -ENOMEM;

	/* Copy REPORTDATA from the user buffer */
	if (copy_from_user(reportmac, u64_to_user_ptr(req.reportmac),
				req.rpm_len)) {
		ret = -EFAULT;
		goto out;
	}

	/*
	 * Verify REPORTMACSTRUCT using "TDG.MR.VERIFYREPORT" TDCALL.
	 *
	 * Verify whether REPORTMACSTRUCT is created on current TEE on
	 * the current platform. Refer to section 8.5.11
	 * TDG.MR.VERIFYREPORT leaf in the TDX Module 1.5 Specification
	 * for detailed information.
	 */
	ret = __tdx_module_call(TDX_VERIFYREPORT, virt_to_phys(reportmac),
				0, 0, 0, NULL);
	if (ret) {
		pr_debug("VERIFYREPORT TDCALL failed, status:%lx\n", ret);
		ret = -EIO;
		goto out;
	}

	/* Copy TDREPORT back to the user buffer */
	if (copy_to_user(u64_to_user_ptr(req.reportmac), reportmac,
				req.rpm_len))
		ret = -EFAULT;

out:
	kfree(reportmac);
	return ret;
}

static long tdx_guest_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	long ret = -EINVAL;

	switch (cmd) {
	case TDX_CMD_GET_REPORT:
		ret = tdx_get_report(argp);
		break;
	case TDX_CMD_GET_QUOTE:
		ret = tdx_get_quote(argp);
		break;
	case TDX_CMD_VERIFYREPORT:
		ret = tdx_verifyreport(argp);
		break;
	default:
		pr_debug("cmd %d not supported\n", cmd);
		break;
	}

	return ret;
}

static const struct file_operations tdx_guest_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= tdx_guest_ioctl,
	.llseek		= no_llseek,
};

static int __init tdx_guest_init(void)
{
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return -EIO;

	tdx_misc_dev.name = DRIVER_NAME;
	tdx_misc_dev.minor = MISC_DYNAMIC_MINOR;
	tdx_misc_dev.fops = &tdx_guest_fops;

	ret = misc_register(&tdx_misc_dev);
	if (ret) {
		pr_err("misc device registration failed\n");
		return ret;
	}

	ret = tdx_attest_init(&tdx_misc_dev);
	if (ret) {
		pr_err("attestation init failed\n");
		misc_deregister(&tdx_misc_dev);
		return ret;
	}

	return 0;
}
device_initcall(tdx_guest_init)

/* Reserve an IRQ from x86_vector_domain for TD event notification */
static int __init tdx_arch_init(void)
{
	struct irq_alloc_info info;
	struct irq_cfg *cfg;
	int cpu;

	if (!cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return 0;

	/* Make sure x86 vector domain is initialized */
	if (!x86_vector_domain) {
		pr_err("x86 vector domain is NULL\n");
		return 0;
	}

	init_irq_alloc_info(&info, NULL);

	/*
	 * Event notification vector will be delivered to the CPU
	 * in which TDVMCALL_SETUP_NOTIFY_INTR hypercall is requested.
	 * So set the IRQ affinity to the current CPU.
	 */
	cpu = get_cpu();

	info.mask = cpumask_of(cpu);

	tdx_notify_irq = irq_domain_alloc_irqs(x86_vector_domain, 1,
				NUMA_NO_NODE, &info);

	if (tdx_notify_irq < 0) {
		pr_err("Event notification IRQ allocation failed %d\n",
				tdx_notify_irq);
		goto init_failed;
	}

	irq_set_handler(tdx_notify_irq, handle_edge_irq);

	cfg = irq_cfg(tdx_notify_irq);
	if (!cfg) {
		pr_err("Event notification IRQ config not found\n");
		goto init_failed;
	}

	if (tdx_hcall_set_notify_intr(cfg->vector))
		pr_err("Setting event notification interrupt failed\n");

init_failed:
	put_cpu();
	return 0;
}
arch_initcall(tdx_arch_init);
