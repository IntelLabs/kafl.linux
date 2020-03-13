/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_ARCH_H
#define __KVM_X86_TDX_ARCH_H

#include <linux/types.h>

/*
 * SEAMCALL API function leaf
 */
#define SEAMCALL_TDENTER		0
#define SEAMCALL_TDADDCX		1
#define SEAMCALL_TDADDPAGE		2
#define SEAMCALL_TDADDSEPT		3
#define SEAMCALL_TDADDVPX		4
#define SEAMCALL_TDASSIGNHKID		5
#define SEAMCALL_TDAUGPAGE		6
#define SEAMCALL_TDBLOCK		7
#define SEAMCALL_TDCONFIGKEY		8
#define SEAMCALL_TDCREATE		9
#define SEAMCALL_TDCREATEVP		10
#define SEAMCALL_TDDBGRD		11
#define SEAMCALL_TDDBGRDMEM		12
#define SEAMCALL_TDDBGWR		13
#define SEAMCALL_TDDBGWRMEM		14
#define SEAMCALL_TDDEMOTEPAGE		15
#define SEAMCALL_TDEXTENDMR		16
#define SEAMCALL_TDFINALIZEMR		17
#define SEAMCALL_TDFLUSHVP		18
#define SEAMCALL_TDFLUSHVPDONE		19
#define SEAMCALL_TDFREEHKIDS		20
#define SEAMCALL_TDINIT			21
#define SEAMCALL_TDINITVP		22
#define SEAMCALL_TDPROMOTEPAGE		23
#define SEAMCALL_TDRDPAGEMD		24
#define SEAMCALL_TDRDSEPT		25
#define SEAMCALL_TDRDVPS		26
#define SEAMCALL_TDRECLAIMHKIDS		27
#define SEAMCALL_TDRECLAIMPAGE		28
#define SEAMCALL_TDREMOVEPAGE		29
#define SEAMCALL_TDREMOVESEPT		30
#define SEAMCALL_TDSYSCONFIGKEY		31
#define SEAMCALL_TDSYSINFO		32
#define SEAMCALL_TDSYSINIT		33

#define SEAMCALL_TDSYSINITLP		35
#define SEAMCALL_TDSYSINITTDMR		36
#define SEAMCALL_TDTEARDOWN		37
#define SEAMCALL_TDTRACK		38
#define SEAMCALL_TDUNBLOCK		39
#define SEAMCALL_TDWBCACHE		40
#define SEAMCALL_TDWBINVDPAGE		41
#define SEAMCALL_TDWRSEPT		42
#define SEAMCALL_TDWRVPS		43
#define SEAMCALL_TDSYSSHUTDOWNLP	44
#define SEAMCALL_TDSYSCONFIG		45

#define NR_TDCX_PAGES   4 /* For TDX 1.O, the number of TDCX is 4 */
#define NR_TDVPX_PAGES  5 /* For TDX 1.0, the number of TDVPX is 5 (6-1) */

#define TDX1_MAX_NR_CPUID_CONFIGS 6

struct tdx_cpuid_config {
	u32 leaf;
	u32 sub_leaf;
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
} __packed;

struct tdx_cpuid_value {
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
} __packed;
/*
 * TD_PARAMS is provided as an input to TDINIT, the size of which is 1024B.
 */
struct td_params {
	u64 attributes;
	u64 xfam;
	u32 max_vcpus;
	u32 reserved0;

	u64 eptp_controls;
	u64 exec_controls;
	u16 tsc_frequency;
	u8  reserved1[38];

	u64 mrconfigid[6];
	u64 mrowner[6];
	u64 mrownerconfig[6];
	u64 reserved2[4];

	union {
		struct tdx_cpuid_value cpuid_values[0];
		u8 reserved3[768];
	};
} __packed;

struct tdmr_reserved_area {
	u64 offset;
	u64 size;
} __packed;

struct tdmr_info {
	u64 base;
	u64 size;
	u64 pamt_1g_base;
	u64 pamt_1g_size;
	u64 pamt_2m_base;
	u64 pamt_2m_size;
	u64 pamt_4k_base;
	u64 pamt_4k_size;
	struct tdmr_reserved_area reserved_areas[16];
} __packed __aligned(PAGE_SIZE);

struct cmr_info {
	u64 base;
	u64 size;
} __packed;

struct tdsysinfo_struct {
	/* TDX-SEAM Module Info */
	u32 attributes;
	u32 vendor_id;
	u32 build_date;
	u16 build_num;
	u16 minor_version;
	u16 major_version;
	u8 reserved0[14];
	/* Memory Info */
	u16 max_tdmrs;
	u16 max_reserved_per_tdmr;
	u16 pamt_entry_size;
	u8 reserved1[10];
	/* Control Struct Info */
	u16 tdcs_base_size;
	u8 reserved2[2];
	u16 tdvps_base_size;
	u8 tdvps_xfam_dependent_size;
	u8 reserved3[9];
	/* TD Capabilities */
	u64 attributes_fixed0;
	u64 attributes_fixed1;
	u64 xfam_fixed0;
	u64 xfam_fixed1;
	u8 reserved4[32];
	u32 num_cpuid_config;
	union {
		struct tdx_cpuid_config cpuid_configs[0];
		u8 reserved5[892];
	};
} __packed __aligned(1024);

#endif /* __KVM_X86_TDX_ARCH_H */
