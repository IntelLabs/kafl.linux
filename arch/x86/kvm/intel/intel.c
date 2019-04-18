// SPDX-License-Identifier: GPL-2.0
#include <linux/moduleparam.h>

#ifdef CONFIG_KVM_INTEL_TDX
static bool __read_mostly enable_tdx = 0;
module_param_named(tdx, enable_tdx, bool, 0444);
#else
#define enable_tdx 0
#endif

#include "vmx.c"
#include "tdx.c"

static int __init intel_check_processor_compatibility(void)
{
	int ret;

	ret = vmx_check_processor_compat();
	if (ret)
		return ret;

	if (enable_tdx) {
		ret = tdx_check_processor_compatibility();

		/*
		 * Until concurrent VMs+TDs are allowed, @enable_tdx is defined
		 * as enabling TDX and disabling VMX.  If TDX isn't supported,
		 * reject the module load instead of falling back to VMX, which
		 * is not what would be expected by the user.  In the future,
		 * failure this will disable TDX instead of failing outright.
		 * This applies to hardware setup and enabling as well.
		 */
		if (ret)
			return ret;
	}

	return 0;
}

static __init int intel_hardware_setup(void)
{
	int ret;

	ret = hardware_setup();
	if (ret)
		return ret;

	if (enable_tdx) {
		ret = tdx_hardware_setup();
		if (ret)
			return ret;
	}

	return 0;
}

static int intel_hardware_enable(void)
{
	return hardware_enable();
}

static void intel_hardware_disable(void)
{
	hardware_disable();
}

static bool intel_is_vm_type_supported(unsigned long type)
{
	return type == KVM_X86_LEGACY_VM ||
	       (type == KVM_X86_TDX_VM && enable_tdx);
}

static int intel_vm_init(struct kvm *kvm)
{
	/* TODO: Stop stuffing @vm_type once TDX and VMX can coexist. */
	if (enable_tdx)
		kvm->arch.vm_type = KVM_X86_TDX_VM;

	if (kvm->arch.vm_type == KVM_X86_TDX_VM)
		return tdx_vm_init(kvm);

	return vmx_vm_init(kvm);
}

static struct kvm *intel_vm_alloc(void)
{
	/* TODO: Plumb through @type to here. */
	if (enable_tdx && !emulate_seam)
		return tdx_vm_alloc();

        return vmx_vm_alloc();
}

static void intel_vm_free(struct kvm *kvm)
{
	if (is_td(kvm) && !emulate_seam)
		return tdx_vm_free(kvm);

	vmx_vm_free(kvm);
}

static void intel_vm_destroy(struct kvm *kvm)
{
	if (is_td(kvm))
		tdx_vm_destroy(kvm);
}

static int intel_vcpu_create(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_create(vcpu);

	return vmx_create_vcpu(vcpu);
}

static void intel_vcpu_run(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_run(vcpu);

	return vmx_vcpu_run(vcpu);
}

static void intel_vcpu_free(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_free(vcpu);

	return vmx_free_vcpu(vcpu);
}

static void intel_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_reset(vcpu, init_event);

	return vmx_vcpu_reset(vcpu, init_event);
}

static void intel_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	return vmx_vcpu_load(vcpu, cpu);
}

static void intel_vcpu_put(struct kvm_vcpu *vcpu)
{
	return vmx_vcpu_put(vcpu);
}

static int intel_handle_exit(struct kvm_vcpu *vcpu,
			     enum exit_fastpath_completion fastpath)
{
	if (is_td_vcpu(vcpu) && !emulate_seam)
		return tdx_handle_exit(vcpu, fastpath);

	return vmx_handle_exit(vcpu, fastpath);
}

static void intel_handle_exit_irqoff(struct kvm_vcpu *vcpu,
				     enum exit_fastpath_completion *fastpath)
{
	if (is_td_vcpu(vcpu) && !emulate_seam)
		return tdx_handle_exit_irqoff(vcpu);

	vmx_handle_exit_irqoff(vcpu, fastpath);
}

static int intel_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	if (is_td_vcpu(vcpu))
		return tdx_set_msr(vcpu, msr_info);

	return vmx_set_msr(vcpu, msr_info);
}

static int intel_smi_allowed(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return 0;

	return vmx_smi_allowed(vcpu);
}

static int intel_pre_enter_smm(struct kvm_vcpu *vcpu, char *smstate)
{
	if (WARN_ON_ONCE(is_td_vcpu(vcpu)))
		return 0;

	return vmx_pre_enter_smm(vcpu, smstate);
}

static int intel_pre_leave_smm(struct kvm_vcpu *vcpu, const char *smstate)
{
	if (WARN_ON_ONCE(is_td_vcpu(vcpu)))
		return 0;

	return vmx_pre_leave_smm(vcpu, smstate);
}

static int intel_enable_smi_window(struct kvm_vcpu *vcpu)
{
	return 0;
}

static bool intel_umip_emulated(void)
{
	/* TODO: Handle this when VMs and TDs aren't mutually exclusive. */
	if (enable_tdx)
		return false;

	return vmx_umip_emulated();
}

static bool intel_is_emulatable(struct kvm_vcpu *vcpu, void *insn, int insn_len)
{
	if (is_td_vcpu(vcpu))
		return tdx_is_emulatable(vcpu, insn, insn_len);

	return vmx_is_emulatable(vcpu, insn, insn_len);
}

static bool intel_apic_init_signal_blocked(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return true;

	return vmx_apic_init_signal_blocked(vcpu);
}

static int intel_mem_enc_op(struct kvm *kvm, void __user *argp)
{
	return -ENOTTY;
}

static void intel_set_virtual_apic_mode(struct kvm_vcpu *vcpu)
{
	return vmx_set_virtual_apic_mode(vcpu);
}

static void intel_apicv_post_state_restore(struct kvm_vcpu *vcpu)
{
	return vmx_apicv_post_state_restore(vcpu);
}

static bool intel_check_apicv_inhibit_reasons(ulong bit)
{
	ulong supported = BIT(APICV_INHIBIT_REASON_DISABLE) |
			  BIT(APICV_INHIBIT_REASON_HYPERV);

	return supported & BIT(bit);
}

static void intel_hwapic_irr_update(struct kvm_vcpu *vcpu, int max_irr)
{
	return vmx_hwapic_irr_update(vcpu, max_irr);
}

static void intel_hwapic_isr_update(struct kvm_vcpu *vcpu, int max_isr)
{
	return vmx_hwapic_isr_update(vcpu, max_isr);
}

static bool intel_guest_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	return vmx_guest_apic_has_interrupt(vcpu);
}

static int intel_sync_pir_to_irr(struct kvm_vcpu *vcpu)
{
	return vmx_sync_pir_to_irr(vcpu);
}

static void intel_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector)
{
	return vmx_deliver_posted_interrupt(vcpu, vector);
}

static void intel_cpuid_update(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu) && !emulate_seam)
		return;

	return vmx_cpuid_update(vcpu);
}

static struct kvm_x86_ops intel_x86_ops __ro_after_init = {
	.cpu_has_kvm_support = cpu_has_kvm_support,
	.disabled_by_bios = vmx_disabled_by_bios,
	.check_processor_compatibility = intel_check_processor_compatibility,
	.hardware_setup = intel_hardware_setup,
	.hardware_unsetup = hardware_unsetup,
	.hardware_enable = intel_hardware_enable,
	.hardware_disable = intel_hardware_disable,
	.cpu_has_accelerated_tpr = report_flexpriority,
	.has_emulated_msr = vmx_has_emulated_msr,

	.is_vm_type_supported = intel_is_vm_type_supported,
	.vm_init = intel_vm_init,
	.vm_alloc = intel_vm_alloc,
	.vm_free = intel_vm_free,
	.vm_destroy = intel_vm_destroy,
	.vcpu_create = intel_vcpu_create,

	.run = intel_vcpu_run,
	.vcpu_free = intel_vcpu_free,
	.vcpu_reset = intel_vcpu_reset,

	.prepare_guest_switch = vmx_prepare_switch_to_guest,
	.vcpu_load = intel_vcpu_load,
	.vcpu_put = intel_vcpu_put,

	.update_bp_intercept = update_exception_bitmap,
	.get_msr_feature = vmx_get_msr_feature,
	.get_msr = vmx_get_msr,
	.set_msr = intel_set_msr,
	.get_segment_base = vmx_get_segment_base,
	.get_segment = vmx_get_segment,
	.set_segment = vmx_set_segment,
	.get_cpl = vmx_get_cpl,
	.get_cs_db_l_bits = vmx_get_cs_db_l_bits,
	.decache_cr0_guest_bits = vmx_decache_cr0_guest_bits,
	.decache_cr4_guest_bits = vmx_decache_cr4_guest_bits,
	.set_cr0 = vmx_set_cr0,
	.set_cr3 = vmx_set_cr3,
	.set_cr4 = vmx_set_cr4,
	.set_efer = vmx_set_efer,
	.get_idt = vmx_get_idt,
	.set_idt = vmx_set_idt,
	.get_gdt = vmx_get_gdt,
	.set_gdt = vmx_set_gdt,
	.get_dr6 = vmx_get_dr6,
	.set_dr6 = vmx_set_dr6,
	.set_dr7 = vmx_set_dr7,
	.sync_dirty_debug_regs = vmx_sync_dirty_debug_regs,
	.cache_reg = vmx_cache_reg,
	.get_rflags = vmx_get_rflags,
	.set_rflags = vmx_set_rflags,

	.tlb_flush = vmx_flush_tlb,
	.tlb_flush_gva = vmx_flush_tlb_gva,

	.handle_exit = intel_handle_exit,
	.handle_exit_irqoff = intel_handle_exit_irqoff,
	.skip_emulated_instruction = skip_emulated_instruction,
	.set_interrupt_shadow = vmx_set_interrupt_shadow,
	.get_interrupt_shadow = vmx_get_interrupt_shadow,
	.patch_hypercall = vmx_patch_hypercall,
	.set_irq = vmx_inject_irq,
	.set_nmi = vmx_inject_nmi,
	.queue_exception = vmx_queue_exception,
	.cancel_injection = vmx_cancel_injection,
	.interrupt_allowed = vmx_interrupt_allowed,
	.nmi_allowed = vmx_nmi_allowed,
	.get_nmi_mask = vmx_get_nmi_mask,
	.set_nmi_mask = vmx_set_nmi_mask,
	.enable_nmi_window = enable_nmi_window,
	.enable_irq_window = enable_irq_window,
	.update_cr8_intercept = update_cr8_intercept,
	.set_virtual_apic_mode = intel_set_virtual_apic_mode,
	.set_apic_access_page_addr = vmx_set_apic_access_page_addr,
	.refresh_apicv_exec_ctrl = vmx_refresh_apicv_exec_ctrl,
	.load_eoi_exitmap = vmx_load_eoi_exitmap,
	.apicv_post_state_restore = intel_apicv_post_state_restore,
	.check_apicv_inhibit_reasons = intel_check_apicv_inhibit_reasons,
	.hwapic_irr_update = intel_hwapic_irr_update,
	.hwapic_isr_update = intel_hwapic_isr_update,
	.guest_apic_has_interrupt = intel_guest_apic_has_interrupt,
	.sync_pir_to_irr = intel_sync_pir_to_irr,
	.deliver_posted_interrupt = intel_deliver_posted_interrupt,
	.dy_apicv_has_pending_interrupt = pi_has_pending_interrupt,

	.set_tss_addr = vmx_set_tss_addr,
	.set_identity_map_addr = vmx_set_identity_map_addr,
	.get_tdp_level = get_ept_level,
	.get_mt_mask = vmx_get_mt_mask,

	.get_exit_info = vmx_get_exit_info,

	.get_lpage_level = vmx_get_lpage_level,

	.cpuid_update = intel_cpuid_update,

	.rdtscp_supported = vmx_rdtscp_supported,
	.invpcid_supported = vmx_invpcid_supported,

	.set_supported_cpuid = vmx_set_supported_cpuid,

	.has_wbinvd_exit = cpu_has_vmx_wbinvd_exit,

	.read_l1_tsc_offset = vmx_read_l1_tsc_offset,
	.write_l1_tsc_offset = vmx_write_l1_tsc_offset,

	.set_tdp_cr3 = vmx_set_cr3,

	.check_intercept = vmx_check_intercept,
	.mpx_supported = vmx_mpx_supported,
	.xsaves_supported = vmx_xsaves_supported,
	.pt_supported = vmx_pt_supported,
	.pku_supported = vmx_pku_supported,

	.request_immediate_exit = vmx_request_immediate_exit,

	.sched_in = vmx_sched_in,

	.slot_enable_log_dirty = vmx_slot_enable_log_dirty,
	.slot_disable_log_dirty = vmx_slot_disable_log_dirty,
	.flush_log_dirty = vmx_flush_log_dirty,
	.enable_log_dirty_pt_masked = vmx_enable_log_dirty_pt_masked,
	.write_log_dirty = vmx_write_pml_buffer,

	.pre_block = vmx_pre_block,
	.post_block = vmx_post_block,

	.pmu_ops = &intel_pmu_ops,

	.update_pi_irte = vmx_update_pi_irte,

#ifdef CONFIG_X86_64
	.set_hv_timer = vmx_set_hv_timer,
	.cancel_hv_timer = vmx_cancel_hv_timer,
#endif

	.setup_mce = vmx_setup_mce,

	.is_emulatable = intel_is_emulatable,
	.umip_emulated = intel_umip_emulated,

	.smi_allowed = intel_smi_allowed,
	.pre_enter_smm = intel_pre_enter_smm,
	.pre_leave_smm = intel_pre_leave_smm,
	.enable_smi_window = intel_enable_smi_window,

	.check_nested_events = NULL,
	.get_nested_state = NULL,
	.set_nested_state = NULL,
	.get_vmcs12_pages = NULL,
	.nested_enable_evmcs = NULL,
	.nested_get_evmcs_version = NULL,
	.apic_init_signal_blocked = intel_apic_init_signal_blocked,

	.mem_enc_op = intel_mem_enc_op,
};

static int __init intel_init(void)
{
	unsigned int vcpu_size = 0, vcpu_align = 0;
	int r;

	/* tdx_early_init must be called before vmx_early_init(). */
	tdx_early_init(&vcpu_size, &vcpu_align);

	vmx_early_init(&vcpu_size, &vcpu_align, &intel_x86_ops);

	r = kvm_init(&intel_x86_ops, vcpu_size, vcpu_align, THIS_MODULE);
	if (r)
		goto err_vmx_late_exit;

	r = vmx_init();
	if (r)
		goto err_kvm_exit;

	r = tdx_init();
	if (r)
		goto err_vmx_exit;

	return 0;

err_vmx_exit:
	vmx_exit();
err_kvm_exit:
	kvm_exit();
err_vmx_late_exit:
	vmx_late_exit();
	return r;
}
module_init(intel_init);

static void intel_exit(void)
{
	tdx_exit();
	vmx_exit();
	kvm_exit();
	vmx_late_exit();
}
module_exit(intel_exit);
