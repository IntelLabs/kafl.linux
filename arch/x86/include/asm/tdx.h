/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/cpufeature.h>
#include <linux/types.h>
#include <linux/device.h>
#include <vdso/limits.h>
#include <asm/vmx.h>

#define TDX_CPUID_LEAF_ID			0x21
#define TDX_HYPERCALL_STANDARD			0
#define TDX_HYPERCALL_VENDOR_KVM		0x4d564b2e584454 /* TDX.KVM */

/*
 * Used in __tdx_module_call() helper function to gather the
 * output registers' values of TDCALL instruction when requesting
 * services from the TDX module. This is software only structure
 * and not related to TDX module/VMM.
 */
struct tdx_module_output {
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
};

/*
 * Used in __tdx_hypercall() helper function to gather the
 * output registers' values of TDCALL instruction when requesting
 * services from the VMM. This is software only structure
 * and not related to TDX module/VMM.
 */
struct tdx_hypercall_output {
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

/*
 * Used by #VE exception handler to gather the #VE exception
 * info from the TDX module. This is software only structure
 * and not related to TDX module/VMM.
 */
struct ve_info {
	u64 exit_reason;
	u64 exit_qual;
	u64 gla;	/* Guest Linear (virtual) Address */
	u64 gpa;	/* Guest Physical (virtual) Address */
	u32 instr_len;
	u32 instr_info;
};

/*
 * Page mapping type enum. This is software construct not
 * part of any hardware or VMM ABI.
 */
enum tdx_map_type {
	TDX_MAP_PRIVATE,
	TDX_MAP_SHARED,
};

#ifdef CONFIG_INTEL_TDX_GUEST

bool is_tdx_guest(void);
bool tdx_debug_enabled(void);
void __init tdx_early_init(void);
void __init tdx_filter_init(void);

/* Helper function used to communicate with the TDX module */
u64 __tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
		      struct tdx_module_output *out);

/* Helper function used to request services from VMM */
u64 __tdx_hypercall(u64 type, u64 fn, u64 r12, u64 r13, u64 r14,
		    u64 r15, struct tdx_hypercall_output *out);

bool tdx_get_ve_info(struct ve_info *ve);

bool tdx_handle_virtualization_exception(struct pt_regs *regs,
					 struct ve_info *ve);

bool tdx_early_handle_ve(struct pt_regs *regs);

bool tdx_allowed_port(int port);

extern phys_addr_t tdx_shared_mask(void);

extern int tdx_hcall_gpa_intent(phys_addr_t start, phys_addr_t end,
				enum tdx_map_type map_type);

extern void tdx_accept_memory(phys_addr_t start, phys_addr_t end);

int tdx_mcall_tdreport(u64 data, u64 reportdata);

int tdx_mcall_rtmr_extend(u64 data, u64 rmtr);

int tdx_hcall_get_quote(u64 data);

extern void (*tdx_event_notify_handler)(void);

bool tdx_guest_dev_authorized(struct device *dev);

bool tdx_filter_enabled(void);

/* Update the trace point symbolic printing too */
enum tdx_fuzz_loc {
	TDX_FUZZ_MSR_READ,
	TDX_FUZZ_MMIO_READ,
	TDX_FUZZ_PORT_IN,
	TDX_FUZZ_CPUID1,
	TDX_FUZZ_CPUID2,
	TDX_FUZZ_CPUID3,
	TDX_FUZZ_CPUID4,
	TDX_FUZZ_MSR_READ_ERR,
	TDX_FUZZ_MSR_WRITE_ERR,
	TDX_FUZZ_MAP_ERR,
	TDX_FUZZ_PORT_IN_ERR,
	TDX_FUZZ_VIRTIO,
	TDX_FUZZ_RANDOM,  /* kAFL */
	TDX_FUZZ_DEBUGFS, /* kAFL */
	TDX_FUZZ_MAX
};

/* forward declare to avoid dependence on virtio.h and ensuing cyclic dependency on device.h */
struct virtio_device;

#if defined(CONFIG_TDX_FUZZ) || defined(CONFIG_TDX_FUZZ_KAFL)
u64 tdx_fuzz(u64 var, uintptr_t addr, int size, enum tdx_fuzz_loc loc);
bool tdx_fuzz_err(enum tdx_fuzz_loc loc);
void tdx_fuzz_virtio_cache_init(struct virtio_device *vdev);
u16 tdx_fuzz_virtio_cache_get_u16(struct virtio_device *vdev, u16 orig_var);
u32 tdx_fuzz_virtio_cache_get_u32(struct virtio_device *vdev, u32 orig_var);
u64 tdx_fuzz_virtio_cache_get_u64(struct virtio_device *vdev, u64 orig_var);
void tdx_fuzz_virtio_cache_refresh(struct device *dev);
#else
static inline u64 tdx_fuzz(u64 var, uintptr_t addr, int size, enum tdx_fuzz_loc loc) { return var; };
static inline bool tdx_fuzz_err(enum tdx_fuzz_loc loc) { return false; }
static inline void tdx_fuzz_virtio_cache_init(struct virtio_device *vdev) { }
static inline u16 tdx_fuzz_virtio_cache_get_u16(struct virtio_device *vdev, u16 orig_var)
{
	return orig_var;
}

static inline u32 tdx_fuzz_virtio_cache_get_u32(struct virtio_device *vdev, u32 orig_var)
{
	return orig_var;
}

static inline u64 tdx_fuzz_virtio_cache_get_u64(struct virtio_device *vdev, u64 orig_var)
{
	return orig_var;
}
static inline void tdx_fuzz_virtio_cache_refresh(struct device *dev) { }
#endif

/*
 * To support I/O port access in decompressor or early kernel init
 * code, since #VE exception handler cannot be used, use paravirt
 * model to implement __in/__out macros which will in turn be used
 * by in{b,w,l}()/out{b,w,l} I/O helper macros used in kernel. Details
 * about __in/__out macro usage can be found in arch/x86/include/asm/io.h
 */
#ifdef BOOT_COMPRESSED_MISC_H

bool early_is_tdx_guest(void);

/*
 * Helper function used for making hypercall for "in"
 * instruction. It will be called from __in IO macro
 * If IO is failed, it will return all 1s.
 */
static inline unsigned int tdx_io_in(int size, int port)
{
	struct tdx_hypercall_output out;

	__tdx_hypercall(TDX_HYPERCALL_STANDARD, EXIT_REASON_IO_INSTRUCTION,
			size, 0, port, 0, &out);

	return out.r10 ? UINT_MAX : out.r11;
}

/*
 * Helper function used for making hypercall for "out"
 * instruction. It will be called from __out IO macro
 */
static inline void tdx_io_out(int size, int port, u64 value)
{
	struct tdx_hypercall_output out;

	__tdx_hypercall(TDX_HYPERCALL_STANDARD, EXIT_REASON_IO_INSTRUCTION,
			size, 1, port, value, &out);
}

#define __out(bwl, bw, sz)						\
do {									\
	if (early_is_tdx_guest()) {					\
		tdx_io_out(sz, port, value);				\
	} else {							\
		asm volatile("out" #bwl " %" #bw "0, %w1" : :		\
				"a"(value), "Nd"(port));		\
	}								\
} while (0)
#define __in(bwl, bw, sz)						\
do {									\
	if (early_is_tdx_guest()) {					\
		value = tdx_io_in(sz, port);				\
	} else {							\
		asm volatile("in" #bwl " %w1, %" #bw "0" :		\
				"=a"(value) : "Nd"(port));		\
	}								\
} while (0)
#endif

#else

static inline bool is_tdx_guest(void) { return false; }
static inline void tdx_early_init(void) { };

static inline bool tdx_early_handle_ve(struct pt_regs *regs) { return false; }

static inline phys_addr_t tdx_shared_mask(void) { return 0; }

static inline int tdx_hcall_gpa_intent(phys_addr_t start, phys_addr_t end,
				enum tdx_map_type map_type)
{
	return -ENODEV;
}

static inline bool tdx_guest_dev_authorized(struct device *dev)
{
	return dev->authorized;
}

static inline bool tdx_filter_enabled(void) { return true; }

#endif /* CONFIG_INTEL_TDX_GUEST */

#if defined(CONFIG_KVM_GUEST) && defined(CONFIG_INTEL_TDX_GUEST)
static inline long tdx_kvm_hypercall(unsigned int nr, unsigned long p1,
				     unsigned long p2, unsigned long p3,
				     unsigned long p4)
{
	struct tdx_hypercall_output out;
	u64 err;

	err = __tdx_hypercall(TDX_HYPERCALL_VENDOR_KVM, nr, p1, p2,
			      p3, p4, &out);

	/*
	 * Non zero return value means buggy TDX module (which is fatal).
	 * So use BUG_ON() to panic.
	 */
	BUG_ON(err);

	return out.r10;
}
#else
static inline long tdx_kvm_hypercall(unsigned int nr, unsigned long p1,
				     unsigned long p2, unsigned long p3,
				     unsigned long p4)
{
	return -ENODEV;
}
#endif /* CONFIG_INTEL_TDX_GUEST && CONFIG_KVM_GUEST */
#endif /* _ASM_X86_TDX_H */
