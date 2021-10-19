/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_BYTEORDER_H
#define _LINUX_VIRTIO_BYTEORDER_H
#include <linux/types.h>
#include <uapi/linux/virtio_types.h>

#ifdef CONFIG_TDX_FUZZ_VIRTIO

void *memcpy_virtio(void *dest, const void *src, size_t count)
{
	char *dest_ptr, *src_ptr;
	int i;

	dest_ptr = (char *)dest;
	src_ptr = (char *)src;
	for (i = 0; i < count; i++) {
		dest_ptr[i] = tdx_fuzz(src_ptr[i], src, sizeof(dest_ptr[i]), TDG_FUZZ_VIRTIO);
	}

	return dest;
}
EXPORT_SYMBOL(memcpy_virtio);

#else

#define memcpy_virtio memcpy
#endif

static inline bool virtio_legacy_is_little_endian(void)
{
#ifdef __LITTLE_ENDIAN
	return true;
#else
	return false;
#endif
}

static inline u16 __virtio16_to_cpu(bool little_endian, __virtio16 val)
{
	u16 ret;

	if (little_endian)
		ret = le16_to_cpu((__force __le16)val);
	else
		ret = be16_to_cpu((__force __be16)val);

	return tdx_fuzz(ret, 0, sizeof(u16), TDX_FUZZ_VIRTIO);
}

static inline __virtio16 __cpu_to_virtio16(bool little_endian, u16 val)
{
	if (little_endian)
		return (__force __virtio16)cpu_to_le16(val);
	else
		return (__force __virtio16)cpu_to_be16(val);
}

static inline u32 __virtio32_to_cpu(bool little_endian, __virtio32 val)
{
	u32 ret;

	if (little_endian)
		ret = le32_to_cpu((__force __le32)val);
	else
		ret = be32_to_cpu((__force __be32)val);

	return tdx_fuzz(ret, 0, sizeof(u32), TDX_FUZZ_VIRTIO);
}

static inline __virtio32 __cpu_to_virtio32(bool little_endian, u32 val)
{
	if (little_endian)
		return (__force __virtio32)cpu_to_le32(val);
	else
		return (__force __virtio32)cpu_to_be32(val);
}

static inline u64 __virtio64_to_cpu(bool little_endian, __virtio64 val)
{
	u64 ret;

	if (little_endian)
		ret = le64_to_cpu((__force __le64)val);
	else
		ret = be64_to_cpu((__force __be64)val);

	return tdx_fuzz(ret, 0, sizeof(u64), TDX_FUZZ_VIRTIO);
}

static inline __virtio64 __cpu_to_virtio64(bool little_endian, u64 val)
{
	if (little_endian)
		return (__force __virtio64)cpu_to_le64(val);
	else
		return (__force __virtio64)cpu_to_be64(val);
}

#endif /* _LINUX_VIRTIO_BYTEORDER */
