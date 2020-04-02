// SPDX-License-Identifier: GPL-2.0-only
/*
 * TDX_SEAMCALL_test
 *
 * Copyright (C) 2019, Intel.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * Author:
 *   Zhang Chen <chen.zhang@intel.com>
 *
 */
#include <linux/bits.h>
#include <linux/kvm.h>

#include <fcntl.h>
#include <limits.h>
#include <kvm_random.h>
#include <kvm_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <test_util.h>
#include <unistd.h>
#include <processor.h>

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef __aligned
#define __aligned(x)                    __attribute__((__aligned__(x)))
#endif

#define PAGE_SIZE	4096
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#include "../../../../../arch/x86/kvm/intel/tdx_arch.h"

static int kvm_fd;

#undef SEAMCALL_VERBOSE

static inline void __seamcall(struct kvm_seamcall *seamcall)
{
	long ret;

	memset(&seamcall->out, 0, sizeof(seamcall->out));

#ifdef SEAMCALL_VERBOSE
	printf("SEAMCALL[%llu] in = 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n",
	       seamcall->in.rax, seamcall->in.rcx, seamcall->in.rdx,
	       seamcall->in.r8, seamcall->in.r9, seamcall->in.r10);
#endif

	ret = ioctl(kvm_fd, KVM_SEAMCALL, seamcall);
	TEST_ASSERT(!ret, "KVM_SEAMCALL failed, ret: %ld, errno: %d", ret, errno);

#ifdef SEAMCALL_VERBOSE
	printf("SEAMCALL[%llu] out = 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n",
	       seamcall->in.rax, seamcall->out.rax, seamcall->out.rcx, seamcall->out.rdx,
	       seamcall->out.r8, seamcall->out.r9, seamcall->out.r10);
#endif
}

static inline u64 seamcall(u64 rax, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10)
{
	struct kvm_seamcall seamcall;

	seamcall.in.rax = rax;
	seamcall.in.rcx = rcx;
	seamcall.in.rdx = rdx;
	seamcall.in.r8  = r8;
	seamcall.in.r9  = r9;
	seamcall.in.r10 = r10;

	__seamcall(&seamcall);

	return seamcall.out.rax;
}

#define seamcall5(op, rcx, rdx, r8, r9)						\
({										\
	u64 err = seamcall(SEAMCALL_##op, rcx, rdx, r8, r9, rand_u64());	\
										\
	TEST_ASSERT(!err, "SEAMCALL[" #op "] failed, error code: 0x%llx", err);	\
})

#define seamcall4(op, rcx, rdx, r8) seamcall5(op, (rcx), (rdx), (r8), rand_u64())
#define seamcall3(op, rcx, rdx)     seamcall4(op, (rcx), (rdx), rand_u64())
#define seamcall2(op, rcx)	    seamcall3(op, (rcx), rand_u64())
#define seamcall1(op)		    seamcall2(op, rand_u64())

static void do_random_seamcalls(void)
{
	struct kvm_seamcall seamcall;
	int i;

	for (i = 0; i < 1000; i++) {
		/* Generate a valid(ish) leaf most of the time. */
		if (rand_bool_p(90))
			seamcall.in.rax = __rand_u8(64);
		else
			seamcall.in.rax = rand_u64();

		seamcall.in.rcx = rand_pa_or_u64();
		seamcall.in.rdx = rand_pa_or_u64();
		seamcall.in.r8  = rand_pa_or_u64();
		seamcall.in.r9  = rand_pa_or_u64();
		seamcall.in.r10 = rand_pa_or_u64();

		__seamcall(&seamcall);
		TEST_ASSERT(seamcall.out.rax,
			    "SEAMCALL[%lu](0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) succeeded",
			    seamcall.in.rax, seamcall.in.rcx, seamcall.in.rdx,
			    seamcall.in.r8,  seamcall.in.r9,  seamcall.in.r10);
	}
}

static inline u64 __pa(void *va)
{
	struct kvm_va_to_pa addr;
	long ret;

	addr.va = (u64)va;

	ret = ioctl(kvm_fd, KVM_TRANSLATE_VA_TO_PA, &addr);
	TEST_ASSERT(!ret, "VA_TO_PA failed, ret: %ld, errno: %d", ret, errno);
	return addr.pa;
}

int main(int argc, char **argv)
{
	struct cmr_info cmrs[TDX1_MAX_NR_CMRS];
	struct tdsysinfo_struct sysinfo;
	struct kvm_vm *vm;

	kvm_fd = open(KVM_DEV_PATH, O_RDWR);
	TEST_ASSERT(kvm_fd >= 0, "failed to open /dev/kvm kvm_fd: %i errno: %i",
		    kvm_fd, errno);

	init_random(parse_seed(argc, argv));

	/* Create a dummy VM to coerce KVM into doing VMXON. */
	vm = vm_create_default(0, 0, NULL);

	seamcall2(TDSYSINIT, 0);

	seamcall1(TDSYSINITLP);

	seamcall5(TDSYSINFO, __pa(&sysinfo), sizeof(sysinfo),
		  __pa(&cmrs), ARRAY_SIZE(cmrs));
	TEST_ASSERT(sysinfo.vendor_id == 0x8086, "Bad vendor_id: %ld",
		    sysinfo.vendor_id);

	do_random_seamcalls();

	close(kvm_fd);
	kvm_vm_free(vm);
	return 0;
}
