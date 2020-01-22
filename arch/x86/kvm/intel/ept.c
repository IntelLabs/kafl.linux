// SPDX-License-Identifier: GPL-2.0-only

#include "capabilities.h"
#include "ept.h"

void ept_enable_tdp(void)
{
	const u64 a_mask = enable_ept_ad_bits ? VMX_EPT_ACCESS_BIT : 0ull;
	const u64 d_mask = enable_ept_ad_bits ? VMX_EPT_DIRTY_BIT : 0ull;
	const u64 p_mask = (cpu_has_vmx_ept_execute_only() ? 0ull :
			    VMX_EPT_READABLE_MASK) | VMX_EPT_SUPPRESS_VE_BIT;

	kvm_mmu_set_spte_init_value(VMX_EPT_SUPPRESS_VE_BIT);

	kvm_mmu_set_mask_ptes(VMX_EPT_READABLE_MASK, a_mask, d_mask, 0ull,
		VMX_EPT_EXECUTABLE_MASK, p_mask, VMX_EPT_RWX_MASK, 0ull);

	kvm_mmu_set_mmio_spte_mask(VMX_EPT_SUPPRESS_VE_BIT, 0, 0);

	kvm_enable_tdp();
}
