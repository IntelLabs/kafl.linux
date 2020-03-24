/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/bitsperlong.h>
#include <asm/errno.h>
#include <asm/kvm_vcpu_regs.h>
#include <asm/nospec-branch.h>

#define WORD_SIZE (BITS_PER_LONG / 8)

#define VCPU_RAX	__VCPU_REGS_RAX * WORD_SIZE
#define VCPU_RCX	__VCPU_REGS_RCX * WORD_SIZE
#define VCPU_RDX	__VCPU_REGS_RDX * WORD_SIZE
#define VCPU_RBX	__VCPU_REGS_RBX * WORD_SIZE
/* Intentionally omit RSP as it's context switched by hardware */
#define VCPU_RBP	__VCPU_REGS_RBP * WORD_SIZE
#define VCPU_RSI	__VCPU_REGS_RSI * WORD_SIZE
#define VCPU_RDI	__VCPU_REGS_RDI * WORD_SIZE

#ifdef CONFIG_X86_64
#define VCPU_R8		__VCPU_REGS_R8  * WORD_SIZE
#define VCPU_R9		__VCPU_REGS_R9  * WORD_SIZE
#define VCPU_R10	__VCPU_REGS_R10 * WORD_SIZE
#define VCPU_R11	__VCPU_REGS_R11 * WORD_SIZE
#define VCPU_R12	__VCPU_REGS_R12 * WORD_SIZE
#define VCPU_R13	__VCPU_REGS_R13 * WORD_SIZE
#define VCPU_R14	__VCPU_REGS_R14 * WORD_SIZE
#define VCPU_R15	__VCPU_REGS_R15 * WORD_SIZE
#endif

#ifdef CONFIG_KVM_INTEL_TDX
#define TDENTER 		0
#define EXIT_REASON_TDCALL	77
#define TDENTER_ERROR_BIT	63
#define seamcall 		.byte 0x66,0x0f,0x01,0xcf
#endif

	.text

/**
 * vmx_vmenter - VM-Enter the current loaded VMCS
 *
 * %RFLAGS.ZF:	!VMCS.LAUNCHED, i.e. controls VMLAUNCH vs. VMRESUME
 *
 * Returns:
 *	%RFLAGS.CF is set on VM-Fail Invalid
 *	%RFLAGS.ZF is set on VM-Fail Valid
 *	%RFLAGS.{CF,ZF} are cleared on VM-Success, i.e. VM-Exit
 *
 * Note that VMRESUME/VMLAUNCH fall-through and return directly if
 * they VM-Fail, whereas a successful VM-Enter + VM-Exit will jump
 * to vmx_vmexit.
 */
SYM_FUNC_START(vmx_vmenter)
	/* EFLAGS.ZF is set if VMCS.LAUNCHED == 0 */
	je 2f

1:	vmresume
	ret

2:	vmlaunch
	ret

3:	cmpb $0, kvm_rebooting
	je 4f
	ret
4:	ud2

	.pushsection .fixup, "ax"
5:	jmp 3b
	.popsection

	_ASM_EXTABLE(1b, 5b)
	_ASM_EXTABLE(2b, 5b)

SYM_FUNC_END(vmx_vmenter)

/**
 * vmx_vmexit - Handle a VMX VM-Exit
 *
 * Returns:
 *	%RFLAGS.{CF,ZF} are cleared on VM-Success, i.e. VM-Exit
 *
 * This is vmx_vmenter's partner in crime.  On a VM-Exit, control will jump
 * here after hardware loads the host's state, i.e. this is the destination
 * referred to by VMCS.HOST_RIP.
 */
SYM_FUNC_START(vmx_vmexit)
#ifdef CONFIG_RETPOLINE
	ALTERNATIVE "jmp .Lvmexit_skip_rsb", "", X86_FEATURE_RETPOLINE
	/* Preserve guest's RAX, it's used to stuff the RSB. */
	push %_ASM_AX

	/* IMPORTANT: Stuff the RSB immediately after VM-Exit, before RET! */
	FILL_RETURN_BUFFER %_ASM_AX, RSB_CLEAR_LOOPS, X86_FEATURE_RETPOLINE

	pop %_ASM_AX
.Lvmexit_skip_rsb:
#endif
	ret
SYM_FUNC_END(vmx_vmexit)

/**
 * __vmx_vcpu_run - Run a vCPU via a transition to VMX guest mode
 * @vmx:	struct vcpu_vmx * (forwarded to vmx_update_host_rsp)
 * @regs:	unsigned long * (to guest registers)
 * @launched:	%true if the VMCS has been launched
 *
 * Returns:
 *	0 on VM-Exit, 1 on VM-Fail
 */
SYM_FUNC_START(__vmx_vcpu_run)
	push %_ASM_BP
	mov  %_ASM_SP, %_ASM_BP
#ifdef CONFIG_X86_64
	push %r15
	push %r14
	push %r13
	push %r12
#else
	push %edi
	push %esi
#endif
	push %_ASM_BX

	/*
	 * Save @regs, _ASM_ARG2 may be modified by vmx_update_host_rsp() and
	 * @regs is needed after VM-Exit to save the guest's register values.
	 */
	push %_ASM_ARG2

	/* Copy @launched to BL, _ASM_ARG3 is volatile. */
	mov %_ASM_ARG3B, %bl

	/* Adjust RSP to account for the CALL to vmx_vmenter(). */
	lea -WORD_SIZE(%_ASM_SP), %_ASM_ARG2
	call vmx_update_host_rsp

	/* Load @regs to RAX. */
	mov (%_ASM_SP), %_ASM_AX

	/* Check if vmlaunch or vmresume is needed */
	cmpb $0, %bl

	/* Load guest registers.  Don't clobber flags. */
	mov VCPU_RBX(%_ASM_AX), %_ASM_BX
	mov VCPU_RCX(%_ASM_AX), %_ASM_CX
	mov VCPU_RDX(%_ASM_AX), %_ASM_DX
	mov VCPU_RSI(%_ASM_AX), %_ASM_SI
	mov VCPU_RDI(%_ASM_AX), %_ASM_DI
	mov VCPU_RBP(%_ASM_AX), %_ASM_BP
#ifdef CONFIG_X86_64
	mov VCPU_R8 (%_ASM_AX),  %r8
	mov VCPU_R9 (%_ASM_AX),  %r9
	mov VCPU_R10(%_ASM_AX), %r10
	mov VCPU_R11(%_ASM_AX), %r11
	mov VCPU_R12(%_ASM_AX), %r12
	mov VCPU_R13(%_ASM_AX), %r13
	mov VCPU_R14(%_ASM_AX), %r14
	mov VCPU_R15(%_ASM_AX), %r15
#endif
	/* Load guest RAX.  This kills the @regs pointer! */
	mov VCPU_RAX(%_ASM_AX), %_ASM_AX

	/* Enter guest mode */
	call vmx_vmenter

	/* Jump on VM-Fail. */
	jbe 2f

	/* Temporarily save guest's RAX. */
	push %_ASM_AX

	/* Reload @regs to RAX. */
	mov WORD_SIZE(%_ASM_SP), %_ASM_AX

	/* Save all guest registers, including RAX from the stack */
	__ASM_SIZE(pop) VCPU_RAX(%_ASM_AX)
	mov %_ASM_BX,   VCPU_RBX(%_ASM_AX)
	mov %_ASM_CX,   VCPU_RCX(%_ASM_AX)
	mov %_ASM_DX,   VCPU_RDX(%_ASM_AX)
	mov %_ASM_SI,   VCPU_RSI(%_ASM_AX)
	mov %_ASM_DI,   VCPU_RDI(%_ASM_AX)
	mov %_ASM_BP,   VCPU_RBP(%_ASM_AX)
#ifdef CONFIG_X86_64
	mov %r8,  VCPU_R8 (%_ASM_AX)
	mov %r9,  VCPU_R9 (%_ASM_AX)
	mov %r10, VCPU_R10(%_ASM_AX)
	mov %r11, VCPU_R11(%_ASM_AX)
	mov %r12, VCPU_R12(%_ASM_AX)
	mov %r13, VCPU_R13(%_ASM_AX)
	mov %r14, VCPU_R14(%_ASM_AX)
	mov %r15, VCPU_R15(%_ASM_AX)
#endif

	/* Clear RAX to indicate VM-Exit (as opposed to VM-Fail). */
	xor %eax, %eax

	/*
	 * Clear all general purpose registers except RSP and RAX to prevent
	 * speculative use of the guest's values, even those that are reloaded
	 * via the stack.  In theory, an L1 cache miss when restoring registers
	 * could lead to speculative execution with the guest's values.
	 * Zeroing XORs are dirt cheap, i.e. the extra paranoia is essentially
	 * free.  RSP and RAX are exempt as RSP is restored by hardware during
	 * VM-Exit and RAX is explicitly loaded with 0 or 1 to return VM-Fail.
	 */
1:	xor %ebx, %ebx
	xor %ecx, %ecx
	xor %edx, %edx
	xor %esi, %esi
	xor %edi, %edi
	xor %ebp, %ebp
#ifdef CONFIG_X86_64
	xor %r8d,  %r8d
	xor %r9d,  %r9d
	xor %r10d, %r10d
	xor %r11d, %r11d
	xor %r12d, %r12d
	xor %r13d, %r13d
	xor %r14d, %r14d
	xor %r15d, %r15d
#endif

	/* "POP" @regs. */
	add $WORD_SIZE, %_ASM_SP
	pop %_ASM_BX

#ifdef CONFIG_X86_64
	pop %r12
	pop %r13
	pop %r14
	pop %r15
#else
	pop %esi
	pop %edi
#endif
	pop %_ASM_BP
	ret

	/* VM-Fail.  Out-of-line to avoid a taken Jcc after VM-Exit. */
2:	mov $1, %eax
	jmp 1b
SYM_FUNC_END(__vmx_vcpu_run)

#ifdef CONFIG_KVM_INTEL_TDX
/**
 * __tdx_vcpu_run - Call SEAMCALL(TDENTER) to run a TD vcpu
 * @tdvpr:	physical address of TDVPR
 * @regs:	void * (to registers of TDVCPU)
 * @gpr_mask:	non-zero if guest registers need to be loaded prior to TDENTER
 *
 * Returns:
 *	TD-Exit Reason
 *
 * Note: KVM doesn't support using XMM in its hypercalls, it's the HyperV
 *	 code's responsibility to save/restore XMM registers on TDVMCALL.
 */
SYM_FUNC_START(__tdx_vcpu_run)
	push %rbp
	mov  %rsp, %rbp

	push %r15
	push %r14
	push %r13
	push %r12
	push %rbx

	/* Save @regs, which is needed after TDENTER to capture output. */
	push %rsi

	/* Load @tdvpr to RCX */
	mov %rdi, %rcx

	/* No need to load guest GPRs if the last exit wasn't a TDVMCALL. */
	test %dx, %dx
	je 1f

	/* Load @regs to RAX, which will be clobbered with $TDENTER anyways. */
	mov %rsi, %rax

	mov VCPU_RBX(%rax), %rbx
	mov VCPU_RDX(%rax), %rdx
	mov VCPU_RBP(%rax), %rbp
	mov VCPU_RSI(%rax), %rsi
	mov VCPU_RDI(%rax), %rdi

	mov VCPU_R8 (%rax),  %r8
	mov VCPU_R9 (%rax),  %r9
	mov VCPU_R10(%rax), %r10
	mov VCPU_R11(%rax), %r11
	mov VCPU_R12(%rax), %r12
	mov VCPU_R13(%rax), %r13
	mov VCPU_R14(%rax), %r14
	mov VCPU_R15(%rax), %r15

	/*  Load TDENTER to RAX.  This kills the @regs pointer! */
1:	mov $TDENTER, %rax

2:	seamcall

	/* Skip to the exit path if TDENTER failed. */
	bt $TDENTER_ERROR_BIT, %rax
	jc 4f

	/* Temporarily save the TD-Exit reason. */
	push %rax

	/* check if TD-exit due to TDVMCALL */
	cmp $EXIT_REASON_TDCALL, %ax

	/* Reload @regs to RAX. */
	mov 8(%rsp), %rax

	/* Jump on non-TDVMCALL */
	jne 3f

	/* Save all output from SEAMCALL(TDENTER) */
	mov %rbx, VCPU_RBX(%rax)
	mov %rbp, VCPU_RBP(%rax)
	mov %rsi, VCPU_RSI(%rax)
	mov %rdi, VCPU_RDI(%rax)
	mov %r10, VCPU_R10(%rax)
	mov %r11, VCPU_R11(%rax)
	mov %r12, VCPU_R12(%rax)
	mov %r13, VCPU_R13(%rax)
	mov %r14, VCPU_R14(%rax)
	mov %r15, VCPU_R15(%rax)

3:	mov %rcx, VCPU_RCX(%rax)
	mov %rdx, VCPU_RDX(%rax)
	mov %r8,  VCPU_R8 (%rax)
	mov %r9,  VCPU_R9 (%rax)

	/*
	 * Clear all general purpose registers except RSP and RAX to prevent
	 * speculative use of the guest's values.
	 */
	xor %rbx, %rbx
	xor %rcx, %rcx
	xor %rdx, %rdx
	xor %rsi, %rsi
	xor %rdi, %rdi
	xor %rbp, %rbp
	xor %r8,  %r8
	xor %r9,  %r9
	xor %r10, %r10
	xor %r11, %r11
	xor %r12, %r12
	xor %r13, %r13
	xor %r14, %r14
	xor %r15, %r15

	/* Restore the TD-Exit reason to RAX for return. */
	pop %rax

	/* "POP" @regs. */
4:	add $8, %rsp
	pop %rbx
	pop %r12
	pop %r13
	pop %r14
	pop %r15

	pop %rbp
	ret

5:	cmpb $0, kvm_rebooting
	je 6f
	mov $-EFAULT, %rax
	jmp 4b
6:	ud2
	_ASM_EXTABLE(2b, 5b)

SYM_FUNC_END(__tdx_vcpu_run)
#endif
