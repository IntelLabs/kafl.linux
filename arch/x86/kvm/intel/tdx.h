/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_H
#define __KVM_X86_TDX_H

#include <linux/list.h>
#include <linux/kvm_host.h>

#include "tdx_arch.h"

extern bool __read_mostly emulate_seam;

#ifdef CONFIG_KVM_INTEL_TDX

struct kvm_tdx {
	struct kvm kvm;

	hpa_t tdr;
	hpa_t tdcs[NR_TDCX_PAGES];

	u32 max_vcpus;
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;

	hpa_t tdvpr;
	hpa_t tdvpx[NR_TDVPX_PAGES];

	struct list_head cpu_list;
	int cpu;
};

struct tdx_capabilities {
	u8 tdcs_nr_pages;
	u8 tdvpx_nr_pages;

	u64 attrs_fixed0;
	u64 attrs_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;
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

#else

struct kvm_tdx;
struct vcpu_tdx;

static inline bool is_td(struct kvm *kvm) { return false; }
static inline bool is_td_vcpu(struct kvm_vcpu *vcpu) { return false; }
static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm) { return NULL; }
static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu) { return NULL; }

#endif /* CONFIG_KVM_INTEL_TDX */

#endif /* __KVM_X86_TDX_H */
