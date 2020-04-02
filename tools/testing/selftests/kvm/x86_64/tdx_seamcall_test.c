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

static bool verbose;
static int kvm_fd;

static inline u64 seamcall(u64 rax, u64 rcx, u64 rdx, u64 r8, u64 r9, u64 r10)
{
	struct kvm_seamcall seamcall;
	long ret;

	memset(&seamcall.out, 0, sizeof(seamcall.out));

	seamcall.in.rax = rax;
	seamcall.in.rcx = rcx;
	seamcall.in.rdx = rdx;
	seamcall.in.r8  = r8;
	seamcall.in.r9  = r9;
	seamcall.in.r10 = r10;

	ret = ioctl(kvm_fd, KVM_SEAMCALL, &seamcall);
	TEST_ASSERT(!ret, "KVM_SEAMCALL failed, ret: %ld, errno: %d", ret, errno);

	if (verbose)
		printf("SEAMCALL[%lu] out = 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n",
		       rax, seamcall.out.rax, seamcall.out.rcx, seamcall.out.rdx,
		       seamcall.out.r8, seamcall.out.r9, seamcall.out.r10);
	return seamcall.out.rax;
}

static inline u64 seamcall5(u64 rax, u64 rcx, u64 rdx, u64 r8, u64 r9)
{
	return seamcall(rax, rcx, rdx, r8, r9, rand_u64());
}
static inline u64 seamcall4(u64 rax, u64 rcx, u64 rdx, u64 r8)
{
	return seamcall5(rax, rcx, rdx, r8, rand_u64());
}
static inline u64 seamcall3(u64 rax, u64 rcx, u64 rdx)
{
	return seamcall4(rax, rcx, rdx, rand_u64());
}
static inline u64 seamcall2(u64 rax, u64 rcx)
{
	return seamcall3(rax, rcx, rand_u64());
}
static inline u64 seamcall1(u64 rax)
{
	return seamcall2(rax, rand_u64());
}

static void do_random_seamcalls(void)
{
	u64 leaf, rcx, rdx, r8, r9, r10;
	long ret;
	int i;

	for (i = 0; i < 1000; i++) {
		/* Generate a valid(ish) leaf most of the time. */
		if (rand_bool_p(90))
			leaf = __rand_u8(64);
		else
			leaf = rand_u64();

		rcx = rand_pa_or_u64();
		rdx = rand_pa_or_u64();
		r8  = rand_pa_or_u64();
		r9  = rand_pa_or_u64();
		r10 = rand_pa_or_u64();

		if (verbose)
			printf("SEAMCALL[%lu](0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
			       leaf, rcx, rdx, r8, r9, r10);

		ret = seamcall(leaf, rcx, rdx, r8, r9, r10);
		TEST_ASSERT(ret,
			    "SEAMCALL[%lu](0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) succeeded",
			    leaf, rcx, rdx, r8, r9, r10);
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
	u64 ret;

	kvm_fd = open(KVM_DEV_PATH, O_RDWR);
	TEST_ASSERT(kvm_fd >= 0, "failed to open /dev/kvm kvm_fd: %i errno: %i",
		    kvm_fd, errno);

	init_random(parse_seed(argc, argv));

	/* Create a dummy VM to coerce KVM into doing VMXON. */
	vm = vm_create_default(0, 0, NULL);

	ret = seamcall2(SEAMCALL_TDSYSINIT, 0);
	TEST_ASSERT(!ret, "TDSYSINIT failed, error code: 0x%llx", ret);

	ret = seamcall1(SEAMCALL_TDSYSINITLP);
	TEST_ASSERT(!ret, "TDSYSINITLP failed, error code: 0x%llx", ret);

	ret = seamcall5(SEAMCALL_TDSYSINFO, __pa(&sysinfo), sizeof(sysinfo),
			__pa(&cmrs), ARRAY_SIZE(cmrs));
	TEST_ASSERT(!ret, "TDSYSINFO failed, error code: 0x%llx", ret);
	TEST_ASSERT(sysinfo.vendor_id == 0x8086, "Bad vendor_id: %ld",
		    sysinfo.vendor_id);

	do_random_seamcalls();

	close(kvm_fd);
	kvm_vm_free(vm);
	return 0;
}
