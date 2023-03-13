// SPDX-License-Identifier: GPL-2.0-only
#ifndef __KVM_X86_EPT_H
#define __KVM_X86_EPT_H

#include <linux/kvm_host.h>
#include <linux/trace_events.h>

#include <asm/vmx.h>

#include "mmu.h"
#include "trace.h"
#include "vmx.h"
#include "x86.h"

void ept_enable_tdp(void);

static inline int ept_handle_ept_violation(struct kvm_vcpu *vcpu, gpa_t gpa,
                                           unsigned long exit_qualification)
{
#if 1
	u64 error_code;

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
#else
	return -1;
#endif	
}

#endif /* __KVM_X86_EPT_H */
