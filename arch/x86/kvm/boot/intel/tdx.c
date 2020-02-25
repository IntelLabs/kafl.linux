// SPDX-License-Identifier: GPL-2.0
#include <linux/earlycpio.h>
#include <linux/fs.h>

#include <asm/cpu.h>
#include <asm/kvm_boot.h>

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

void __init tdx_seam_init(void)
{
	const char *sigstruct_name = "intel-seam/libtdx.so.sigstruct";
	const char *seamldr_name = "intel-seam/seamldr.acm";
	const char *module_name = "intel-seam/libtdx.so";

        struct cpio_data module, sigstruct, seamldr;

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

	/* TODO: Invoke SEAMCALLs on BSP, configure TDMRs, etc... */

	setup_force_cpu_cap(X86_FEATURE_TDX);
}
