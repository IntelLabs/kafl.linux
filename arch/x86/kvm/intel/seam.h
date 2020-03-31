/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_SEAM_H
#define __KVM_X86_SEAM_H

#include "vmx.h"
#include "tdx.h"

#define TDCALL_TDVMCALL		0
#define TDCALL_TDINFO		1
#define TDCALL_TDEXTENDRTMR     2
#define TDCALL_TDGETVEINFO	3
#define TDCALL_TDREPORT		4
#define TDCALL_TDSETCPUIDVE	5
#define TDCALL_TDACCEPTPAGE	6

#define TDCALL_ENABLE_VE	100

/*
 * The architectural fields are defined in the SDM and must match exactly, this
 * struct this is used to reference the #VE info page!  Note, the order and
 * sizes of the non-architectural are deliberately chosen so as to avoid having
 * to tag the struct as __packed.
 */
struct tdx_ve_info {
        /* Architectural */
	u32 exit_reason;
	u32 busy;
	u64 exit_qual;
	u64 gla;
	u64 gpa;
	u16 eptp_index;

	/* Non-architectural */
	u16 instr_len;
	u32 instr_info;
} __aligned(PAGE_SIZE);

struct vcpu_seam {
	/*
	 * struct vcpu_vmx absolutely must be first when emulating SEAM, as
	 * SEAM does vCPU creation using what is effectively a vcpu_seam object
	 * masquerading as a vcpu_vmx object.
	 */
	struct vcpu_vmx	vmx;

	/* Embedded because generic KVM handles vCPU allocation. */
	struct vcpu_tdx tdx;

	struct tdx_ve_info ve_info;

	bool ve_injection_enabled;
	bool tdvmcall_exit;
	u16 tdvmcall_regs;
};

void seam_exit(void);

int seam_tdcreate(struct kvm *kvm);
int seam_tdcreatevp(struct kvm_vcpu *vcpu);
void seam_tdfreevp(hpa_t tdvpr);
void seam_tdinitvp(hpa_t tdvpr, bool init_event);
void seam_tdenter(hpa_t tdvpr);

/* No SEAMCALL equivalent, purely a software necessity. */
int __init seam_init(struct kvm_x86_ops *__tdx_ops);

#endif /* __KVM_X86_SEAM_H */
