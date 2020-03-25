// SPDX-License-Identifier: GPL-2.0-only
#ifndef __KVM_X86_INTEL_COMMON_H
#define __KVM_X86_INTEL_COMMON_H

#include <linux/kvm_host.h>

#include <asm/traps.h>

#include "vmcs.h"
#include "x86.h"

/*
 * Trigger machine check on the host. We assume all the MSRs are already set up
 * by the CPU and that we still run on the same CPU as the MCE occurred on.
 * We pass a fake environment to the machine check handler because we want
 * the guest to be always treated like user space, no matter what context
 * it used internally.
 */
static inline void kvm_machine_check(void)
{
#if defined(CONFIG_X86_MCE) && defined(CONFIG_X86_64)
	struct pt_regs regs = {
		.cs = 3, /* Fake ring 3 no matter what the guest ran on */
		.flags = X86_EFLAGS_IF,
	};

	do_machine_check(&regs, 0);
#endif
}

static inline void intel_handle_exception_nmi_irqoff(struct kvm_vcpu *vcpu,
                                                     u32 intr_info)
{
	/* Handle machine checks before interrupts are enabled */
	if (is_machine_check(intr_info))
		kvm_machine_check();

	/* We need to handle NMIs before interrupts are enabled */
	if (is_nmi(intr_info)) {
		kvm_before_interrupt(vcpu);
		asm("int $2");
		kvm_after_interrupt(vcpu);
	}
}

#endif /* __KVM_X86_INTEL_COMMON_H */
