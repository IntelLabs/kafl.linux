/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_ARCH_H
#define __KVM_X86_TDX_ARCH_H

#include <linux/types.h>

#define NR_TDCX_PAGES   4 /* For TDX 1.O, the number of TDCX is 4 */
#define NR_TDVPX_PAGES  5 /* For TDX 1.0, the number of TDVPX is 5 (6-1) */

/*
 * TD_PARAMS is provided as an input to TDINIT, the size of which is 1024B.
 */
struct td_params {
	u64 attributes;
	u64 xfam;
	u32 max_vcpus;
	u32 reserved0;

	u16 eptp_controls;
	u8  reserved1[6];

	u64 exec_controls;
	u16 tsc_frequency;
	u8  reserved2[38];

	u64 mrconfigid[6];
	u64 mrowner[6];
	u64 mrownerconfig[6];
	u64 reserved3[4];

	union {
		struct {
			u32 eax;
			u32 ebx;
			u32 ecx;
			u32 edx;
		} cpuid_configs[0];
		u8 reserved4[768];
	};
} __packed;

#endif /* __KVM_X86_TDX_ARCH_H */
