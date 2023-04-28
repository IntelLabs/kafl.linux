/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_H
#define __KVM_X86_TDX_H

#include <linux/list.h>
#include <linux/kvm_host.h>

#include "tdx_arch.h"
#include "posted_intr.h"

//TODO move to seam commit
extern bool __read_mostly emulate_seam;

struct tdx_td_page {
	unsigned long va;
	hpa_t pa;
	bool added;
};

struct kvm_tdx {
	struct kvm kvm;

	struct tdx_td_page tdr;
	struct tdx_td_page tdcs[TDX1_NR_TDCX_PAGES];

	int hkid;

	int cpuid_nent;
	struct kvm_cpuid_entry2 cpuid_entries[KVM_MAX_CPUID_ENTRIES];
};

union tdx_exit_reason {
	struct {
		/* 31:0 mirror the VMX Exit Reason format */
		u64 basic		: 16;
		u64 reserved16		: 1;
		u64 reserved17		: 1;
		u64 reserved18		: 1;
		u64 reserved19		: 1;
		u64 reserved20		: 1;
		u64 reserved21		: 1;
		u64 reserved22		: 1;
		u64 reserved23		: 1;
		u64 reserved24		: 1;
		u64 reserved25		: 1;
		u64 reserved26		: 1;
		u64 enclave_mode	: 1;
		u64 smi_pending_mtf	: 1;
		u64 smi_from_vmx_root	: 1;
		u64 reserved30		: 1;
		u64 failed_vmentry	: 1;

		/* 63:32 are TDX specific */
		u64 details_l1		: 8;
		u64 class		: 8;
		u64 reserved61_48	: 14;
		u64 non_recoverable	: 1;
		u64 error		: 1;
	};
	u64 full;
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;

	struct tdx_td_page tdvpr;
	struct tdx_td_page tdvpx[TDX1_NR_TDVPX_PAGES];

	struct list_head cpu_list;

	/* Posted interrupt descriptor */
	struct pi_desc pi_desc;

	union {
		struct {
			union {
				struct {
					u16 gpr_mask;
					u16 xmm_mask;
				};
				u32 regs_mask;
			};
			u32 reserved;
		};
		u64 rcx;
	} tdvmcall;

	union tdx_exit_reason exit_reason;
};

static inline bool is_td(struct kvm *kvm)
{
	return kvm->arch.vm_type == KVM_X86_TDX_VM;
}

static inline bool is_td_vcpu(struct kvm_vcpu *vcpu)
{
	return is_td(vcpu->kvm);
}

static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_tdx, kvm);
}

static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_tdx, vcpu);
}

#endif /* __KVM_X86_TDX_H */
