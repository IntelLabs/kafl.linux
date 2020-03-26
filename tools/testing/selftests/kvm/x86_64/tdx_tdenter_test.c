// SPDX-License-Identifier: GPL-2.0-only
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

int main(int argc, char **argv)
{
	struct kvm_tdenter tdenter;
	struct kvm_vm *vm;
	u64 ret;
	int fd;

	fd = open(KVM_DEV_PATH, O_RDWR);
	TEST_ASSERT(fd >= 0, "failed to open /dev/kvm fd: %i errno: %i",
		    fd, errno);

	/* Create a dummy VM to coerce KVM into doing VMXON. */
	vm = vm_create_default(0, 0, NULL);

	memset(&tdenter, 0, sizeof(tdenter));
	tdenter.regs[0] = 0xbeef;

	ret = ioctl(fd, KVM_TDENTER, &tdenter);
	TEST_ASSERT(!ret, "KVM_TDENTER failed, ret: %ld, errno: %d", ret, errno);
	TEST_ASSERT(tdenter.regs[0] != 0xbeef, "TD-Exit Reason not filled\n");

	close(fd);
	kvm_vm_free(vm);
	return 0;
}
