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

#include "../../../../../arch/x86/kvm/intel/tdx_arch.h"

static u8 x86_phys_bits;
static bool verbose;
static int kvm_fd;

static inline void cpuid(unsigned int *eax, unsigned int *ebx,
			 unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile("cpuid"
	    : "=a" (*eax),
	      "=b" (*ebx),
	      "=c" (*ecx),
	      "=d" (*edx)
	    : "0" (*eax), "2" (*ecx)
	    : "memory");
}

static inline unsigned int cpuid_eax(unsigned int leaf)
{
	unsigned int eax, ebx, ecx, edx;

	eax = leaf;
	ecx = 0;
	cpuid(&eax, &ebx, &ecx, &edx);

	return eax;
}

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

static inline u64 rand_pa(void)
{
	return __rand_u64(GENMASK_ULL(x86_phys_bits - 1, 12));
}

static inline bool rand_bool(void)
{
	return rand_u32() < 0x80000000u;
}

static inline bool rand_bool_p(int percentage)
{
	if (percentage >= 100)
		return true;

	return rand_u32() < ((-1u / 100) * percentage);
}

static inline u64 rand_pa_or_u64(void)
{
	if (rand_bool())
		return rand_pa();
	return rand_u64();
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
	TEST_ASSERT(fd >= 0, "failed to open /dev/urandom, fd: %i errno: %i",
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

int main(int argc, char **argv)
{
	struct kvm_vm *vm;
	u64 ret;

	kvm_fd = open(KVM_DEV_PATH, O_RDWR);
	TEST_ASSERT(kvm_fd >= 0, "failed to open /dev/kvm kvm_fd: %i errno: %i",
		    kvm_fd, errno);

	x86_phys_bits = cpuid_eax(0x80000008) & 0xff;

	init_random_seed(argc, argv);

	/* Create a dummy VM to coerce KVM into doing VMXON. */
	vm = vm_create_default(0, 0, NULL);

	ret = seamcall2(SEAMCALL_TDSYSINIT, 0);
	TEST_ASSERT(!ret, "TDSYSINIT failed, error code: 0x%llx", ret);

	ret = seamcall1(SEAMCALL_TDSYSINITLP);
	TEST_ASSERT(!ret, "TDSYSINITLP failed, error code: 0x%llx", ret);

	do_random_seamcalls();

	close(kvm_fd);
	kvm_vm_free(vm);
	return 0;
}
