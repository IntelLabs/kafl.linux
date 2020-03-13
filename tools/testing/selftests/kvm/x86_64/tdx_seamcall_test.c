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

#include <fcntl.h>
#include <limits.h>
#include <kvm_util.h>
#include <linux/kvm.h>
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

#include "../../../../../arch/x86/kvm/intel/tdx_arch.h"

static inline u8 __rand_u8(u8 mask)
{
	return (u8)rand() & mask;
}

static inline u8 rand_u8(void)
{
	return __rand_u8(0xff);
}

static inline u16 __rand_u16(u16 mask)
{
	return (u16)rand() & mask;
}

static inline u16 rand_u16(void)
{
	return __rand_u16(0xffff);
}

static inline u32 __rand_u32(u32 mask)
{
	return (u32)rand() & mask;
}

static inline u32 rand_u32(void)
{
	return __rand_u32(-1u);
}

static inline u64 __rand_u64(u64 mask)
{
	return (u64)rand() & mask;
}

static inline u64 rand_u64(void)
{
	return __rand_u64(-1ull);
}

static unsigned int parse_seed(int argc, char **argv)
{
	unsigned int seed;
	char *tmp = NULL;
	int c;

	c = getopt(argc, argv, "s:");
	if (c == -1)
		return 0;

	TEST_ASSERT(c == 's', "Unknown option '%s'", c);

	seed = (unsigned int)strtoul(optarg, &tmp, 0);
	TEST_ASSERT(*tmp == '\0' && tmp != optarg,
		    "Unabled to parse seed '%s'\n", optarg);

	return seed;
}

static void init_random_seed(int argc, char **argv)
{
	unsigned int seed;
	int fd, ret;

	seed = parse_seed(argc, argv);
	if (seed)
		goto init_srand;

	fd = open("/dev/urandom", O_RDONLY);
	TEST_ASSERT(fd >= 0, "failed to open /dev/kvm, fd: %i errno: %i",
		    fd, errno);

	ret = read(fd, &seed, sizeof(seed));
	TEST_ASSERT(ret == sizeof(seed),
		    "failed read() on /dev/urandom, ret: %i errno: %i",
		    ret, errno);
	close(fd);

init_srand:
	printf("TDX random seed: %u\n", seed);
	srand(seed);
}

static inline u64 seamcall(int fd, u64 rax, u64 rcx, u64 rdx, u64 r8, u64 r9,
			   u64 r10)
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

	ret = ioctl(fd, KVM_SEAMCALL, &seamcall);
	TEST_ASSERT(!ret, "KVM_SEAMCALL failed, ret: %ld, errno: %d", ret, errno);

	return seamcall.out.rax;
}

static inline u64 seamcall5(int fd, u64 rax, u64 rcx, u64 rdx, u64 r8, u64 r9)
{
	return seamcall(fd, rax, rcx, rdx, r8, r9, rand_u64());
}
static inline u64 seamcall4(int fd, u64 rax, u64 rcx, u64 rdx, u64 r8)
{
	return seamcall5(fd, rax, rcx, rdx, r8, rand_u64());
}
static inline u64 seamcall3(int fd, u64 rax, u64 rcx, u64 rdx)
{
	return seamcall4(fd, rax, rcx, rdx, rand_u64());
}
static inline u64 seamcall2(int fd, u64 rax, u64 rcx)
{
	return seamcall3(fd, rax, rcx, rand_u64());
}
static inline u64 seamcall1(int fd, u64 rax)
{
	return seamcall2(fd, rax, rand_u64());
}

int main(int argc, char **argv)
{
	struct kvm_vm *vm;
	u64 ret;
	int fd;

	fd = open(KVM_DEV_PATH, O_RDWR);
	TEST_ASSERT(fd >= 0, "failed to open /dev/kvm fd: %i errno: %i",
		    fd, errno);

	init_random_seed(argc, argv);

	/* Create a dummy VM to coerce KVM into doing VMXON. */
	vm = vm_create_default(0, 0, NULL);

	ret = seamcall2(fd, SEAMCALL_TDSYSINIT, 0);
	TEST_ASSERT(!ret, "TDSYSINIT failed, error code: 0x%llx", ret);

	ret = seamcall1(fd, SEAMCALL_TDSYSINITLP);
	TEST_ASSERT(!ret, "TDSYSINITLP failed, error code: 0x%llx", ret);

	close(fd);
	kvm_vm_free(vm);
	return 0;
}
