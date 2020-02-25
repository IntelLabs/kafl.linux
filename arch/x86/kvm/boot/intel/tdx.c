// SPDX-License-Identifier: GPL-2.0
#include <linux/earlycpio.h>
#include <linux/fs.h>
#include <linux/percpu.h>
#include <linux/memblock.h>

#include <asm/cpu.h>
#include <asm/kvm_boot.h>
#include <asm/virtext.h>
#include <asm/tlbflush.h>

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

/*
 * Define __seamcall used by boot code to override the default in tdx_ops.h.
 * The default BUG()s on faults, which is undesirable during boot, and calls
 * kvm_spurious_fault(), which isn't linkable if KVM is built as a module.
 * RAX contains '0' on success, TDX-SEAM errno on failure, vector on fault.
 */
#define seamcall ".byte 0x66,0x0f,0x01,0xcf"

#define __seamcall			\
	"1:" seamcall "\n\t"		\
	"2: \n\t"			\
	_ASM_EXTABLE_FAULT(1b, 2b)

#include "intel/tdx_arch.h"
#include "intel/tdx_ops.h"
#include "intel/tdx_errno.h"

#include "intel/vmcs.h"

/*
 * TODO: better to have kernel boot parameter to let admin control whether to
 * enable TDX with sysprof or not.
 *
 * Or how to decide tdx_sysprof??
 */
static bool tdx_sysprof;

/*
 * TDX system information returned by TDSYSINFO.
 */
static struct tdsysinfo_struct tdx_tdsysinfo __aligned(1024);

/*
 * CMR info array returned by TDSYSINFO.
 *
 * FIXME:
 *
 * TDSYSINFO doesn't return specific error code indicating whether we didn't
 * pass long-enough CMR info array to it, so we just define a maximum value
 * which should be big enough for now -- which is 128, which is twice of
 * maximum number of TDMRs for TDX1.
 *
 * FIXME 2:
 *
 * Use __initdata? It appears they are not needed after kernel boots.
 */
#define MAX_NR_CMRS	128
static struct cmr_info tdx_cmrs[MAX_NR_CMRS] __aligned(512);
static int tdx_nr_cmrs;

/*
 * Well.. I guess a better way is to put cpu_vmxon() into asm/virtext.h,
 * and split kvm_cpu_vmxon() into cpu_vmxon(), and intel_pt_handle_vmx(),
 * so we just only have one cpu_vmxon() in asm/virtext.h..
 */
static inline void cpu_vmxon(u64 vmxon_region)
{
	cr4_set_bits(X86_CR4_VMXE);
	asm volatile ("vmxon %0" : : "m"(vmxon_region));
}

static inline int tdx_vmxon(struct vmcs *vmcs)
{
	u64 msr;

	/*
	 * Can't enable TDX if VMX is unsupported or disabled by BIOS.
	 * cpu_has(X86_FEATURE_VMX) can't be relied on as the BSP calls this
	 * before the kernel has configured feat_ctl().
	 */
	if (!cpu_has_vmx())
		return -ENOTSUPP;

	if (rdmsrl_safe(MSR_IA32_FEAT_CTL, &msr) ||
	    !(msr & FEAT_CTL_LOCKED) ||
	    !(msr & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX))
		return -ENOTSUPP;

	if (rdmsrl_safe(MSR_IA32_VMX_BASIC, &msr))
		return -ENOTSUPP;

	memset(vmcs, 0, PAGE_SIZE);
	vmcs->hdr.revision_id = (u32)msr;

	cpu_vmxon(__pa(vmcs));

	return 0;
}

static long __tdx_init_cpu(struct cpuinfo_x86 *c, unsigned long vmcs)
{
	bool is_bsp = (c == &boot_cpu_data);
	struct tdx_ex_ret ex_ret;
	long ret;

	ret = tdx_vmxon((void *)vmcs);
	if (ret)
		return ret;

	/* For BSP, call TDSYSINIT first for platform-level initialization. */
	if (is_bsp) {
		ret = tdsysinit(tdx_sysprof ? BIT(0) : 0, &ex_ret);
		if (ret)
			goto out;
	}

	/* Call TDSYSINITLP for per-cpu initialization */
	ret = tdsysinitlp(&ex_ret);
	if (ret)
		goto out;

	/*
	 * Call TDSYSINFO right after TDSYSINITTLP on BSP, since constructing
	 * TDMRs needs to be done before kernel page allocator is up (which
	 * means before SMP is up), because it requires to reserve large chunk
	 * of memory (>4MB) which kernel page allocator cannot allocate, and
	 * reserving PAMT requires info returned by TDSYSINFO.
	 */
	if (is_bsp) {
		ret = tdsysinfo(__pa(&tdx_tdsysinfo), sizeof(tdx_tdsysinfo),
				__pa(tdx_cmrs), MAX_NR_CMRS, &ex_ret);
		if (ret)
			goto out;

		tdx_nr_cmrs = ex_ret.nr_cmr_entries;
	}
out:
	cpu_vmxoff();

	return ret;
}

void tdx_init_cpu(struct cpuinfo_x86 *c)
{
	unsigned long vmcs;

	/* BSP does TDSYSINITLP as part of tdx_seam_init(). */
	if (c == &boot_cpu_data)
		return;

	/* Allocate VMCS for VMXON. */
	vmcs = __get_free_page(GFP_KERNEL);
	if (!vmcs) {
		clear_cpu_cap(c, X86_FEATURE_TDX);
		return;
	}

	/* VMXON and TDSYSINITLP shouldn't fail at this point. */
	if (WARN_ON_ONCE(__tdx_init_cpu(c, vmcs)))
		clear_cpu_cap(c, X86_FEATURE_TDX);

	free_page(vmcs);
}

void __init tdx_seam_init(void)
{
	const char *sigstruct_name = "intel-seam/libtdx.so.sigstruct";
	const char *seamldr_name = "intel-seam/seamldr.acm";
	const char *module_name = "intel-seam/libtdx.so";
	struct cpio_data module, sigstruct, seamldr;
	void *vmcs;

        if (!get_builtin_firmware(&module, module_name))
                return;

	/* Use the kernel's fake SEAMLDR when running as a VM. */
        if (boot_cpu_has(X86_FEATURE_HYPERVISOR)) {
                if (seam_load_module(module_name, module.data, module.size))
			return;
	} else {
		if (!get_builtin_firmware(&sigstruct, sigstruct_name))
			return;

		if (!get_builtin_firmware(&seamldr, seamldr_name))
			return;

		/* TODO: invoke GETSEC to run real SEAMLDR. */
	}

	vmcs = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
	if (!vmcs)
		return;

	if (!__tdx_init_cpu(&boot_cpu_data, (unsigned long)vmcs))
		setup_force_cpu_cap(X86_FEATURE_TDX);

	/*
	 * Free VMCS here, since it's harder to free it later, i.e after SMP
	 * is up, because at that time page allocator is already up. VMCS can
	 * be allocated again when needed before TDSYSCONFIG staff.
	 */
	memblock_free(__pa(vmcs), PAGE_SIZE);
}
