// SPDX-License-Identifier: GPL-2.0

#include <linux/slab.h>

bool __read_mostly boot_protected_mode = 1;
module_param_named(pm, boot_protected_mode, bool, 0444);

bool __read_mostly boot_x2apic_mode = 1;
module_param_named(x2apic, boot_x2apic_mode, bool, 0444);

bool __read_mostly debug_mode = 1;
module_param_named(debug, debug_mode, bool, 0444);

bool __read_mostly ve_injection = 1;
module_param(ve_injection, bool, 0444);

static u64 __read_mostly page_shared_mask;

#define TDCALL_TDVMCALL		0
#define TDCALL_TDINFO		1
#define TDCALL_TDEXTENDRTMR     2
#define TDCALL_TDGETVEINFO	3
#define TDCALL_TDREPORT		4
#define TDCALL_TDSETCPUIDVE	5
#define TDCALL_TDACCEPTPAGE	6
#define TDCALL_WR		8

#define TDCALL_ENABLE_VE	100

#define ATTR_SEPT_VE_DISABLE	BIT(28)

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

extern struct kmem_cache *x86_emulator_cache;
extern struct x86_emulate_ctxt *alloc_emulate_ctxt(struct kvm_vcpu *vcpu);

static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu);

static int vmx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info);
static __init int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, u32 *result);
static int vmx_vm_init(struct kvm *kvm);
static int vmx_vcpu_create(struct kvm_vcpu *vcpu);
static void vmx_vcpu_free(struct kvm_vcpu *vcpu);
static void vmx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event);
static void vmx_vcpu_after_set_cpuid(struct kvm_vcpu *vcpu);
static fastpath_t vmx_vcpu_run(struct kvm_vcpu *vcpu);
static int handle_exception_nmi(struct kvm_vcpu *vcpu);
static int handle_ept_violation(struct kvm_vcpu *vcpu);
static int handle_external_interrupt(struct kvm_vcpu *vcpu);
static int handle_triple_fault(struct kvm_vcpu *vcpu);
static int handle_ept_misconfig(struct kvm_vcpu *vcpu);

static inline struct vcpu_seam *to_seam(struct kvm_vcpu *vcpu)
{
	return container_of(to_vmx(vcpu), struct vcpu_seam, vmx);
}

static inline struct kvm_vcpu *to_tdx_vcpu(struct kvm_vcpu *vcpu)
{
	return &to_seam(vcpu)->tdx.vcpu;
}

static int seam_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	/*
	 * Don't allow disabling X2APIC when it's forced on.  If userspace is
	 * stuffing the MSR, just silently override it.
	 */
	if (boot_x2apic_mode && msr_info->index == MSR_IA32_APICBASE &&
	    !(msr_info->data & X2APIC_ENABLE)) {
		if (msr_info->host_initiated)
			msr_info->data |= X2APIC_ENABLE;
		else
			return 1;
	}

	return vmx_set_msr(vcpu, msr_info);
}

static int __init seam_check_processor_compat(void)
{
	u32 ign;

	/*
	 * x2APIC is technically required from a TDX architecture perspective,
	 * but at this point neither firmware nor the kernel *require* x2APIC
	 * to be enabled from the beginning of time.  For simplicitly, start
	 * the TD in in xAPIC and let it transition to x2APIC on its own, i.e.
	 * don't muck with the VMX internals (yet), but still require x2APIC
	 * so that it can be forced in a future patch without adding a new
	 * hardware dependency.
	 *
	 * This is obviously a small subset of required features, but any CPU
	 * that supports #VE and x2APIC will support everything else.
	 *
	 * Note, full APICv support is required for TDX, but lack of APICv is
	 * not not visible to the guest, so don't require it in hardware.
	 */
	if (!(vmcs_config.cpu_based_2nd_exec_ctrl &
	      SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE)) {
		pr_warn("SEAM: CPU doesn't support x2APIC virtualization\n");
		return -EIO;
	}
	if (adjust_vmx_controls(SECONDARY_EXEC_EPT_VIOLATION_VE, 0,
				MSR_IA32_VMX_PROCBASED_CTLS2, &ign)) {
		pr_warn("SEAM: CPU doesn't support EPT violation #VE\n");
		return -EIO;
	}
	return 0;
}

static int seam_tdcreate(struct kvm *kvm)
{
	int ret;
//TODO
#if 0
	u64 val;

	/*
	 * vmx_vm_init() overwrites shadow_mmio_value, hide this funky
	 * emulation depedency from the TDX code.
	 */
	val = kvm->arch.shadow_mmio_value;
	ret = vmx_vm_init(kvm);
	kvm->arch.shadow_mmio_value = val;
#else	
	ret = vmx_vm_init(kvm);
#endif
	return ret;
}

static void flat_seg_setup(int seg)
{
	const struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	unsigned int ar;

	vmcs_write16(sf->selector, 0);
	vmcs_writel(sf->base, 0);
	vmcs_write32(sf->limit, 0xffffffffU);

	/*
	 * G		15
	 * D/B		14
	 * L		13
	 * AVL		12
	 * PRESENT:	7
	 * DPL:		6:5
	 * S:		4
	 * TYPE:	3:0
	 *
	 * ar = G=1 | DB=1 | L=0 | P=1 | DPL=0 | S=0 | TYPE = 3 / 0xB
	 */
	ar = 0xc093;
	if (seg == VCPU_SREG_CS)
		ar |= 0x08; /* code segment */
	vmcs_write32(sf->ar_bytes, ar);
}

static void seam_enable_ve_injection(struct kvm_vcpu *vcpu)
{
	struct vcpu_seam *seam = to_seam(vcpu);

	if (seam->ve_injection_enabled)
		return;
#if 0
	vmcs_write64(VE_INFO_ADDRESS, virt_to_phys(&seam->ve_info));
#endif
	secondary_exec_controls_setbit(to_vmx(vcpu),
				       SECONDARY_EXEC_EPT_VIOLATION_VE);

	seam->ve_injection_enabled = true;
}

static int seam_tdcreatevp(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu *tdx_vcpu = to_tdx_vcpu(vcpu);
	int ret;

	/* Verify SEAM emulation assumptions for vCPU layout. */
	BUILD_BUG_ON(offsetof(struct vcpu_seam, vmx) != 0);

	if (!irqchip_in_kernel(vcpu->kvm)) {
		pr_warn("SEAM: In-kernel IRQ chip for local APIC required.\n");
		return -EINVAL;
	}

	if (!flexpriority_enabled) {
		pr_warn("SEAM: flexpriority module param must be enabled.\n");
		return -EINVAL;
	}

	ret = vmx_vcpu_create(vcpu);
	if (ret)
		return ret;

	tdx_vcpu->kvm = vcpu->kvm;
	tdx_vcpu->run = vcpu->run;
	tdx_vcpu->arch.pio_data = vcpu->arch.pio_data;
	tdx_vcpu->arch.apic = vcpu->arch.apic;

	alloc_emulate_ctxt(tdx_vcpu);

	to_seam(vcpu)->tdx.tdvpr.va = (unsigned long)vcpu;
	to_seam(vcpu)->tdx.tdvpr.pa = virt_to_phys(vcpu);

	return 0;
}

static void seam_tdfreevp(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu *tdx_vcpu = to_tdx_vcpu(vcpu);

	if (tdx_vcpu->arch.emulate_ctxt)
		kmem_cache_free(x86_emulator_cache, tdx_vcpu->arch.emulate_ctxt);
	vmx_vcpu_free(vcpu);
}

static void seam_tdinitvp(struct kvm_vcpu *vcpu, bool init_event)
{
	unsigned long cr0;

	vmx_vcpu_reset(vcpu, init_event);

	/* Because KVM may look at the BSP bit... */
	to_tdx_vcpu(vcpu)->arch.apic_base = vcpu->arch.apic_base;

	/*
	 * Set guest_state_encrypted even for debug_mode to prevent userspace
	 * from overriding the CPU reset state.  For debugging, the bool will
	 * be cleared by seam_vcpu_run(), i.e. post-reset.
	 */
	vcpu->arch.guest_state_encrypted = true;

	if (ve_injection)
		seam_enable_ve_injection(vcpu);

	if (boot_x2apic_mode) {
		struct msr_data msr;

		msr.data = vcpu->arch.apic_base | LAPIC_MODE_X2APIC;
		msr.host_initiated = true;
		WARN_ON(kvm_set_apic_base(vcpu, &msr));
	}

	if (!boot_protected_mode)
		return;

	flat_seg_setup(VCPU_SREG_CS);
	flat_seg_setup(VCPU_SREG_DS);
	flat_seg_setup(VCPU_SREG_ES);
	flat_seg_setup(VCPU_SREG_FS);
	flat_seg_setup(VCPU_SREG_GS);
	flat_seg_setup(VCPU_SREG_SS);

	kvm_rip_write(vcpu, 0xfffffff0UL);

	cr0 = X86_CR0_NE | X86_CR0_ET | X86_CR0_PE;
	vcpu->arch.cr0 = cr0;
	vmx_set_cr0(vcpu, cr0);

	vmx_set_cr4(vcpu, X86_CR4_MCE);
	vmx_set_efer(vcpu, EFER_NX | EFER_LME);

	/* All vCPUs, including APs, are immediately runnable. */
	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
}

static bool seam_is_reflected_exit(u32 exit_reason)
{
	switch (exit_reason) {
	case EXIT_REASON_CPUID:
	case EXIT_REASON_HLT:
	case EXIT_REASON_IO_INSTRUCTION:
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_MSR_WRITE:
	case EXIT_REASON_MWAIT_INSTRUCTION:
	case EXIT_REASON_MONITOR_INSTRUCTION:
	//case EXIT_REASON_VMCALL: // do not intercept VMCALL of type KAFL
	case EXIT_REASON_WBINVD:
		return true;
	}
	return false;
}

static bool seam_inject_ve(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vcpu_seam *seam = to_seam(vcpu);
	struct tdx_ve_info *info = &seam->ve_info;

	if (!seam->ve_injection_enabled)
		return false;

	if (!seam_is_reflected_exit(vmx->exit_reason.basic))
		return false;

	/*
	 * I/O strings are not supported in TDX, guests must unroll the
	 * strings to normal I/O instructions.
	 */
	if (vmx->exit_reason.basic == EXIT_REASON_IO_INSTRUCTION &&
	    unlikely(vmcs_readl(EXIT_QUALIFICATION) & 0x10)) {
		pr_warn("seam: String I/O VMExit @ %lx", vmcs_readl(GUEST_RIP));
		return false;
	}

	/* Many leafs are virtualized by SEAM.  Note, this is not accurate. */
	if (vmx->exit_reason.basic == EXIT_REASON_CPUID) {
		unsigned long leaf = kvm_rax_read(vcpu);
		if (leaf <= 0x1f || (leaf >= 0x80000000u && leaf <= 0x80000008u))
			return false;
	}

	/* Not all MSRs are passed through as they should be... */
	if (vmx->exit_reason.basic == EXIT_REASON_MSR_READ ||
	    vmx->exit_reason.basic == EXIT_REASON_MSR_WRITE) {
		switch (kvm_rcx_read(vcpu)) {
		case MSR_EFER:
		case MSR_IA32_CR_PAT:
		case MSR_STAR:
		case MSR_CSTAR:
		case MSR_LSTAR:
		case MSR_SYSCALL_MASK:
		case MSR_TSC_AUX:
		case MSR_IA32_BNDCFGS:
		case MSR_IA32_XSS:
		case MSR_IA32_SPEC_CTRL:
		case MSR_IA32_PRED_CMD:
		case MSR_IA32_FLUSH_CMD:
		case MSR_IA32_DS_AREA:
			return false;
		}
	}

	/*
	 * Do not overwrite an event being injected by KVM, we'll just have to
	 * skip #VE reflection for this VM-Exit.
	 */
	if (vmcs_read32(VM_ENTRY_INTR_INFO_FIELD) & INTR_INFO_VALID_MASK)
		return false;

	if (info->busy) {
		//TODO
		/* trace_kvm_ve_injection(kvm_rip_read(vcpu), vmx->exit_reason.full, */
		/* 		       -1, -1, -1); */
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			     INTR_INFO_VALID_MASK |
			     INTR_TYPE_HARD_EXCEPTION |
			     INTR_INFO_DELIVER_CODE_MASK |
			     GP_VECTOR);
		return true;
	}

	info->busy = 0xffffffff;
	//TODO full or basic?
	info->exit_reason = vmx->exit_reason.full;
	info->instr_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	if (vmx->exit_reason.basic == EXIT_REASON_IO_INSTRUCTION) {
		info->instr_info = 0;
		info->exit_qual = vmcs_readl(EXIT_QUALIFICATION);
	} else {
		info->instr_info = vmcs_read32(VMX_INSTRUCTION_INFO);
		info->exit_qual = 0;
	}

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		     INTR_INFO_VALID_MASK | INTR_TYPE_HARD_EXCEPTION | VE_VECTOR);

	//TODO
	/* trace_kvm_ve_injection(kvm_rip_read(vcpu), info->exit_reason, */
	/* 	info->instr_len, info->instr_info, info->exit_qual); */

	return true;
}

static void seam_get_ve_info(struct kvm_vcpu *vcpu)
{
	struct tdx_ve_info *info = &to_seam(vcpu)->ve_info;

	if (!info->busy) {
	//TODO	trace_kvm_get_ve_info(kvm_rip_read(vcpu), -1, -1, -1, -1);

		kvm_rax_write(vcpu, -1);
		return;
	}
	info->busy = 0;

	kvm_rax_write(vcpu, 0);
	//TODO full or basic?
	kvm_rcx_write(vcpu, info->exit_reason);
	kvm_rdx_write(vcpu, info->exit_qual);
	kvm_r8_write(vcpu, info->gla);
	kvm_r9_write(vcpu, info->gpa);
	kvm_r10_write(vcpu, ((u64)(info->instr_info) << 32) | info->instr_len);

	//TODO
	/* trace_kvm_get_ve_info(kvm_rip_read(vcpu), info->exit_reason, */
	/* 	info->instr_len, info->instr_info, info->exit_qual); */
}

static void seam_get_tdinfo(struct kvm_vcpu *vcpu)
{
	u64 nr_vcpus = vcpu->kvm->created_vcpus;

	page_shared_mask = BIT_ULL(boot_cpu_data.x86_phys_bits - 1);

	kvm_rax_write(vcpu, 0);
	kvm_rcx_write(vcpu, __ilog2_u64(page_shared_mask) + 1);
	kvm_rdx_write(vcpu, ATTR_SEPT_VE_DISABLE);
	kvm_r8_write(vcpu, (nr_vcpus << 32) | nr_vcpus);
	kvm_r9_write(vcpu, vcpu->vcpu_id);
	kvm_r10_write(vcpu, 0);
}

static void seam_copy_regs(struct kvm_vcpu *dst, struct kvm_vcpu *src, u16 mask)
{
	int i;

	for (i = VCPU_REGS_RDX; i <= VCPU_REGS_R15; i++) {
		if (mask & BIT(i))
			dst->arch.regs[i] = src->arch.regs[i];
	}
}

static fastpath_t seam_tdenter(struct kvm_vcpu *vcpu)
{
	struct vcpu_seam *seam = to_seam(vcpu);
	fastpath_t fastpath;

	/*
	 * Wait until the vCPU is run to enable debugging, so as to prevent
	 * userspace from overriding the CPU reset state.
	 */
	if (debug_mode)
		vcpu->arch.guest_state_encrypted = false;
	
	//printk("SEAM: %s vcpu: %lx,%lx, tdx: %lx,%lx\n",
	//	   	__func__,
	//		vcpu->arch.regs[VCPU_REGS_RIP],
	//		vcpu->arch.regs[VCPU_REGS_RSP],
	//		to_tdx_vcpu(vcpu)->arch.regs[VCPU_REGS_RIP],
	//		to_tdx_vcpu(vcpu)->arch.regs[VCPU_REGS_RSP]
	//	  );


	/*
	 * regs_dirty is set when the SEAMRET was due to TDVMCALL, in which
	 * case the registers are preserved in both directions.  RAX and RCX
	 * are exceptions as they are overwritten by TDX-SEAM.
	 */
	if (seam->tdvmcall_exit) {
		if (vcpu->arch.guest_seamregs_valid) {
			seam_copy_regs(vcpu, to_tdx_vcpu(vcpu), seam->tdvmcall_regs);

			kvm_rax_write(vcpu, 0);
			kvm_rcx_write(vcpu, 0);
			kvm_r10_write(vcpu, 0);
			vcpu->arch.guest_seamregs_valid = false;
		} else {
			WARN_ONCE(1, "SEAM regs invalid, skip seam_copy_regs\n");
		}

		seam->tdvmcall_exit = false;
		seam->tdvmcall_regs = 0;
	}

	do {
		fastpath = vmx_vcpu_run(vcpu);
	} while (seam_inject_ve(vcpu));

	return fastpath;
}

static int seam_complete_userspace_io(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu *tdx_vcpu = to_tdx_vcpu(vcpu);
	int ret;

	ret = tdx_vcpu->arch.complete_userspace_io(tdx_vcpu);
	tdx_vcpu->arch.complete_userspace_io = NULL;
	vcpu->arch.pio.count = 0;
	vcpu->mmio_needed = false;
	return ret;
}

int __tdx_handle_exit(struct kvm_vcpu *vcpu);

static int seamret(struct kvm_vcpu *vcpu, u32 exit_reason)
{
	struct kvm_vcpu *tdx_vcpu = to_tdx_vcpu(vcpu);
	struct vcpu_seam *seam = to_seam(vcpu);
	int ret;
	
	//printk("SEAM: %s vcpu: %lx,%lx, tdx: %lx,%lx\n",
	//	   	__func__,
	//		vcpu->arch.regs[VCPU_REGS_RIP],
	//		vcpu->arch.regs[VCPU_REGS_RSP],
	//		to_tdx_vcpu(vcpu)->arch.regs[VCPU_REGS_RIP],
	//		to_tdx_vcpu(vcpu)->arch.regs[VCPU_REGS_RSP]
	//	  );

	if (exit_reason == EXIT_REASON_TDCALL) {
		seam->tdvmcall_exit = true;
		seam->tdvmcall_regs = kvm_rcx_read(vcpu);
		seam_copy_regs(to_tdx_vcpu(vcpu), vcpu, seam->tdvmcall_regs);
		vcpu->arch.guest_seamregs_valid = true;
	} else {
		seam->tdvmcall_exit = false;
		tdx_vcpu->arch.regs[VCPU_REGS_RCX] = vmcs_readl(EXIT_QUALIFICATION);
		tdx_vcpu->arch.regs[VCPU_REGS_RDX] = 0; /* Unused EXT_EXIT_QUAL */
		tdx_vcpu->arch.regs[VCPU_REGS_R8]  = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
		tdx_vcpu->arch.regs[VCPU_REGS_R9] = vmcs_read32(VM_EXIT_INTR_INFO);
	}
	to_tdx(tdx_vcpu)->exit_reason.full = exit_reason;

	ret = __tdx_handle_exit(tdx_vcpu);
	if (ret)
		return ret;

	if (tdx_vcpu->arch.complete_userspace_io) {
		vcpu->arch.complete_userspace_io = seam_complete_userspace_io;

		if (tdx_vcpu->arch.pio.count) {
			memcpy(&vcpu->arch.pio, &tdx_vcpu->arch.pio,
			       sizeof(vcpu->arch.pio));
		} else {
			vcpu->mmio_needed = tdx_vcpu->mmio_needed;
			vcpu->mmio_is_write = tdx_vcpu->mmio_is_write;
			vcpu->mmio_fragments[0] = tdx_vcpu->mmio_fragments[0];
		}
	}
	return 0;
}

static int seam_emulate_tdcall(struct kvm_vcpu *vcpu)
{
	unsigned long fn, rip;
	int ret;

	if (vmx_get_cpl(vcpu) != 0) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	fn = kvm_rax_read(vcpu);
	//printk("SEAM: %s(%lx)\n", __func__, fn);
	switch (fn) {
	case TDCALL_TDVMCALL:
		if ((kvm_rcx_read(vcpu) >> 32) || (kvm_rcx_read(vcpu) & 0x13)) {
			kvm_inject_gp(vcpu, 0);
			return 1;
		}
		ret = seamret(vcpu, EXIT_REASON_TDCALL);
		break;
	case TDCALL_TDGETVEINFO:
		seam_get_ve_info(vcpu);
		ret = 1;
		break;
	case TDCALL_TDINFO:
		seam_get_tdinfo(vcpu);
		ret = 1;
		break;
	case TDCALL_TDEXTENDRTMR:
	case TDCALL_TDREPORT:
	case TDCALL_TDSETCPUIDVE:
	case TDCALL_TDACCEPTPAGE:
		/* TODO: Emulate other TDCALL leafs */
		kvm_rax_write(vcpu, 0);
		ret = 1;
		break;
	case TDCALL_ENABLE_VE:
		seam_enable_ve_injection(vcpu);
		ret = 1;
		break;
	case TDCALL_WR:
		/* For handling TDX_WR TDCS_NOTIFY_ENABLES
		 * no need to do anything here since
		 * the guest is not expecting anything back */
		kvm_rax_write(vcpu, 0);
		ret = 1;
		break;
	default:
		kvm_inject_gp(vcpu, 0);
		return 1;
	}
	if (ret >= 0) {
		/*
		 * Use the common helper to handle side effects.  Save RIP
		 * and set it directly since VMCS.INSTR_LEN is bogus.
		 */
		rip = kvm_rip_read(vcpu);
		ret = kvm_skip_emulated_instruction(vcpu) && ret;
		kvm_rip_write(vcpu, rip + 4);
	}
	return ret;
}

static int seam_handle_exception(struct kvm_vcpu *vcpu)
{
	unsigned long rip = kvm_get_linear_rip(vcpu);
	u32 intr_info = to_vmx(vcpu)->exit_intr_info;
	struct x86_exception e;
	u32 sig;

	if (!is_td_vcpu(vcpu))
		return handle_exception_nmi(vcpu);

	if (is_invalid_opcode(intr_info) &&
	    !kvm_read_guest_virt(vcpu, rip, &sig, 4, &e) && sig == 0xcc010f66)
		return seam_emulate_tdcall(vcpu);

	/* SEAM returns to the VMM on NMIs and #MCs. */
	if (is_machine_check(intr_info) || is_nmi(intr_info))
		return seamret(vcpu, EXIT_REASON_EXCEPTION_NMI);

	/*
	printk("SEAM: !NMI! intr_info: %x, type=%x, vector=%x, valid=%x\n",
		   	intr_info,
		   	intr_info & INTR_INFO_INTR_TYPE_MASK,
		   	intr_info & INTR_INFO_VECTOR_MASK,
		   	intr_info & INTR_INFO_VALID_MASK);
	*/

	return handle_exception_nmi(vcpu);
}

static int seam_handle_cpuid(struct kvm_vcpu *vcpu)
{
	u32 leaf = kvm_rax_read(vcpu);
	int ret;

	ret = kvm_emulate_cpuid(vcpu);

	if (leaf == TDX_CPUID_LEAF_ID) {
		u32 ident[3];

		memcpy(ident, TDX_IDENT, sizeof(ident));
		kvm_rbx_write(vcpu, ident[0]);
		kvm_rdx_write(vcpu, ident[1]);
		kvm_rcx_write(vcpu, ident[2]);
	}

	return ret;
}


static bool seam_is_emulatable(struct kvm_vcpu *vcpu, void *insn, int insn_len)
{
	if (!to_seam(vcpu)->ve_injection_enabled)
		return true;

	/*
	 * Let VMX emulate APIC accesses, #UDs and any other type of VM-Exit
	 * that will never result in a SEAMRET (because the VM-Exit simply
	 * won't happen when running under TDX-SEAM).
	 */
	if (to_vmx(vcpu)->exit_reason.basic != EXIT_REASON_EPT_VIOLATION)
		return true;

	return false;
}

static int seam_handle_ept_violation(struct kvm_vcpu *vcpu)
{
	if (!is_td_vcpu(vcpu))
		return handle_ept_violation(vcpu);
#if 0
	/* TODO: do <something> for EPT violations on private GPAs */
	if (!is_shared_gpa())
		???
#endif
	if (!to_seam(vcpu)->ve_injection_enabled)
		return handle_ept_violation(vcpu);

	return seamret(vcpu, to_vmx(vcpu)->exit_reason.full);
}

static int seam_handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	if (!is_td_vcpu(vcpu))
		return handle_external_interrupt(vcpu);

	return seamret(vcpu, to_vmx(vcpu)->exit_reason.full);
}

static int seam_handle_triple_fault(struct kvm_vcpu *vcpu)
{
	if (!is_td_vcpu(vcpu))
		return handle_triple_fault(vcpu);

	return seamret(vcpu, to_vmx(vcpu)->exit_reason.full);
}

static int seam_handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	if (!is_td_vcpu(vcpu))
		return handle_ept_misconfig(vcpu);

	return seamret(vcpu, to_vmx(vcpu)->exit_reason.full);
}

static void __init seam_early_init(unsigned int *vcpu_size,
				   unsigned int *vcpu_align)
{

	*vcpu_size = sizeof(struct vcpu_seam);
	*vcpu_align = __alignof__(struct vcpu_tdx);

//	nested = 0;
	enable_pml = 0;
#if IS_ENABLED(CONFIG_HYPERV)
	enlightened_vmcs = 0;
#endif

	if (!enable_ept) {
		pr_warn("SEAM: ignoring user's request to disable EPT\n");
		enable_ept = 1;
	}

	if (!enable_unrestricted_guest) {
		pr_warn("SEAM: ignoring user's request to disable unrestricted guest\n");
		enable_unrestricted_guest = 1;
	}

	kvm_vmx_exit_handlers[EXIT_REASON_EXCEPTION_NMI]	= seam_handle_exception;
	kvm_vmx_exit_handlers[EXIT_REASON_EXTERNAL_INTERRUPT]	= seam_handle_external_interrupt;
	kvm_vmx_exit_handlers[EXIT_REASON_TRIPLE_FAULT]		= seam_handle_triple_fault;
	kvm_vmx_exit_handlers[EXIT_REASON_CPUID]		= seam_handle_cpuid;
	kvm_vmx_exit_handlers[EXIT_REASON_EPT_VIOLATION]	= seam_handle_ept_violation;
	kvm_vmx_exit_handlers[EXIT_REASON_EPT_MISCONFIG]	= seam_handle_ept_misconfig;

	/* Verify SEAM emulation assumptions for vCPU layout. */
	BUILD_BUG_ON(offsetof(struct vcpu_seam, vmx) != 0);
}
