// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO PCI Intel Graphics support
 *
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
 *	Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * Register a device specific region through which to provide read-only
 * access to the Intel IGD opregion.  The register defining the opregion
 * address is also virtualized to prevent user modification.
 */

#include <linux/io.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>

#include "vfio_pci_private.h"

#define OPREGION_SIGNATURE	"IntelGraphicsMem"
#define OPREGION_SIZE		(8 * 1024)
#define OPREGION_PCI_ADDR	0xfc

#define OPREGION_RVDA		0x3ba
#define OPREGION_RVDS		0x3c2
#define OPREGION_VERSION	0x16

#define IGD_GMCH		0x50 /* Graphics Control Register */
#define BDW_GMCH_GMS_SHIFT	8
#define BDW_GMCH_GMS_MASK	0xff

extern struct resource intel_graphics_stolen_res;

static u32 gen9_get_stolen_size(u16 gmch)
{
	gmch >>= BDW_GMCH_GMS_SHIFT;
	gmch &= BDW_GMCH_GMS_MASK;

	if (gmch < 0xf0)
		return gmch << 25; /* 32 MB units */
	else
		/* 4MB increments starting at 0xf0 for 4MB */
		return (gmch - 0xf0 + 1) << 22;
}

static size_t vfio_pci_igd_rw(struct vfio_pci_device *vdev, char __user *buf,
			      size_t count, loff_t *ppos, bool iswrite)
{
	unsigned int i = VFIO_PCI_OFFSET_TO_INDEX(*ppos) - VFIO_PCI_NUM_REGIONS;
	void *base = vdev->region[i].data;
	loff_t pos = *ppos & VFIO_PCI_OFFSET_MASK;
	u16 version;
	u64 rvda;
	u32 rvds;

	if (pos >= vdev->region[i].size || iswrite)
		return -EINVAL;

	count = min(count, (size_t)(vdev->region[i].size - pos));

	version = le16_to_cpu(*(__le16 *)(base + OPREGION_VERSION));
	rvda = le64_to_cpu(*(__le64 *)(base + OPREGION_RVDA));
	rvds = le32_to_cpu(*(__le32 *)(base + OPREGION_RVDS));

	if (vdev->region[i].subtype == VFIO_REGION_SUBTYPE_INTEL_IGD_OPREGION &&
	    version == 0x0200 && rvda && rvds) {
		u32 addr = cpu_to_le32(*(__le32 *)(vdev->vconfig + OPREGION_PCI_ADDR));
		void *vbt_base;
		void *opregionvbt;

		vbt_base = memremap(rvda, rvds, MEMREMAP_WB);
		if (!vbt_base)
			return -ENOMEM;

		opregionvbt = kzalloc(vdev->region[i].size, GFP_KERNEL);
		if (!opregionvbt) {
			memunmap(vbt_base);
			return -ENOMEM;
		}

		/* Stitch VBT after OpRegion if noncontigious */
		memcpy(opregionvbt, base, OPREGION_SIZE);
		memcpy(opregionvbt + OPREGION_SIZE, vbt_base, rvds);

		/* Patch OpRegion 2.0 to 2.1 */
		*(__le16 *)(opregionvbt + OPREGION_VERSION) = 0x0201;
		/* Patch RVDA location after OpRegion */
		*(__le64 *)(opregionvbt + OPREGION_RVDA) = OPREGION_SIZE;

		if (copy_to_user(buf, opregionvbt + pos, count)) {
			kfree(opregionvbt);
			memunmap(vbt_base);
			return -EFAULT;
		}

		kfree(opregionvbt);
		memunmap(vbt_base);
	} else {
		if (copy_to_user(buf, base + pos, count))
			return -EFAULT;
	}

	*ppos += count;

	return count;
}

static void vfio_pci_igd_release(struct vfio_pci_device *vdev,
				 struct vfio_pci_region *region)
{
	memunmap(region->data);
}

static const struct vfio_pci_regops vfio_pci_igd_regops = {
	.rw		= vfio_pci_igd_rw,
	.release	= vfio_pci_igd_release,
};

static int vfio_pci_igd_opregion_init(struct vfio_pci_device *vdev)
{
	__le32 *dwordp = (__le32 *)(vdev->vconfig + OPREGION_PCI_ADDR);
	u32 addr, size, rvds = 0;
	void *base;
	int ret;
	u16 version;
	u64 rvda = 0;

	ret = pci_read_config_dword(vdev->pdev, OPREGION_PCI_ADDR, &addr);
	if (ret)
		return ret;

	if (!addr || !(~addr))
		return -ENODEV;

	base = memremap(addr, OPREGION_SIZE, MEMREMAP_WB);
	if (!base)
		return -ENOMEM;

	if (memcmp(base, OPREGION_SIGNATURE, 16)) {
		memunmap(base);
		return -EINVAL;
	}

	size = le32_to_cpu(*(__le32 *)(base + 16));
	if (!size) {
		memunmap(base);
		return -EINVAL;
	}

	size *= 1024; /* In KB */

	/*
	 * Support OpRegion v2.0+
	 * When VBT data exceeds 6KB size and cannot be within mailbox #4, then
	 * the Extended VBT region is used to hold the VBT data.
	 * RVDA (Relative Address of VBT Data from OpRegion Base) and RVDS
	 * (Raw VBT Data Size) from OpRegion structure member are used to hold the
	 * address from region base and size of VBT data. RVDA/RVDS are not
	 * defined before OpRegion 2.0.
	 * When VBT raw data doesn't exceed 6KB, it's still stored in Mailbox #4
	 * same as previous OpRegion version.
	 *
	 * OpRegion 2.0: If RVDA/RVDS are valid, RVDA stores the absolute physical
	 * address for VBT and may not be contigious after OpRegion. Thus the vfio
	 * region is combined with two memory regions: OpRegion and VBT. The total
	 * size of this vfio region is sum of OpRegion size and VBT size. The r/w
	 * ops will allocate a contigious physical memory to stitch VBT after OpRegion,
	 * patch the in-memory OpRegion to 2.1, RVDA to relative address just
	 * after OpRegion, then copy back to user space requester.
	 *
	 * OpRegion 2.1: If RVDA/RVDS are valid, and RVDA is equal to OpRegion size,
	 * simply map the contigious region which contains both OpRegion and VBT.
	 */
	version = le16_to_cpu(*(__le16 *)(base + OPREGION_VERSION));

	if (version >= 0x0200) {
		rvda = le64_to_cpu(*(__le64 *)(base + OPREGION_RVDA));
		rvds = le32_to_cpu(*(__le32 *)(base + OPREGION_RVDS));

		/*
		 * Valid RVDA/RVDS for OpRegion 2.0+:
		 * 2.0: The vfio region size will be registered as OpRegion Size + RVDS,
		 *      But only OpRegion will be mapped as region base, the read ops
		 *      will allocate another piece of memory and stich VBT after
		 *      OpRegion, patch to valid OpRegion 2.1 and copy back to user space.
		 * 2.1: RVDA is relative address to OpRegion base, never point to
		 *      anything arbitrarily within the OpRegion itself. Current
		 *      extended VBT region always follows OpRegion.
		 */
		if (rvda && rvds && version > 0x0200) {
			if (rvda != size) {
				memunmap(base);
				pci_err(vdev->pdev,
					"Extended VBT does not follow opregion on version 0x%04x\n",
					version);
				return -EINVAL;
			}
			/* region size for OpRegion v2.0+: OpRegion and extended VBT size. */
			size += rvds;
			rvds = 0;
		}
	}

	if (size != OPREGION_SIZE) {
		memunmap(base);
		base = memremap(addr, size, MEMREMAP_WB);
		if (!base)
			return -ENOMEM;
	}

	/*
	 * Register OpRegion with OpRegion size + VBT size for 2.0 and above.
	 * The vfio region could be combined with two mapped memory region in case
	 * OpRegion 2.0 with valid RVDA and RVDS.
	 */
	ret = vfio_pci_register_dev_region(vdev,
		PCI_VENDOR_ID_INTEL | VFIO_REGION_TYPE_PCI_VENDOR_TYPE,
		VFIO_REGION_SUBTYPE_INTEL_IGD_OPREGION,
		&vfio_pci_igd_regops, size + rvds, VFIO_REGION_INFO_FLAG_READ, base);
	if (ret) {
		memunmap(base);
		return ret;
	}

	/* Fill vconfig with the hw value and virtualize register */
	*dwordp = cpu_to_le32(addr);
	memset(vdev->pci_config_map + OPREGION_PCI_ADDR,
	       PCI_CAP_ID_INVALID_VIRT, 4);

	return ret;
}

static size_t vfio_pci_igd_cfg_rw(struct vfio_pci_device *vdev,
				  char __user *buf, size_t count, loff_t *ppos,
				  bool iswrite)
{
	unsigned int i = VFIO_PCI_OFFSET_TO_INDEX(*ppos) - VFIO_PCI_NUM_REGIONS;
	struct pci_dev *pdev = vdev->region[i].data;
	loff_t pos = *ppos & VFIO_PCI_OFFSET_MASK;
	size_t size;
	int ret;

	if (pos >= vdev->region[i].size || iswrite)
		return -EINVAL;

	size = count = min(count, (size_t)(vdev->region[i].size - pos));

	if ((pos & 1) && size) {
		u8 val;

		ret = pci_user_read_config_byte(pdev, pos, &val);
		if (ret)
			return pcibios_err_to_errno(ret);

		if (copy_to_user(buf + count - size, &val, 1))
			return -EFAULT;

		pos++;
		size--;
	}

	if ((pos & 3) && size > 2) {
		u16 val;

		ret = pci_user_read_config_word(pdev, pos, &val);
		if (ret)
			return pcibios_err_to_errno(ret);

		val = cpu_to_le16(val);
		if (copy_to_user(buf + count - size, &val, 2))
			return -EFAULT;

		pos += 2;
		size -= 2;
	}

	while (size > 3) {
		u32 val;

		ret = pci_user_read_config_dword(pdev, pos, &val);
		if (ret)
			return pcibios_err_to_errno(ret);

		val = cpu_to_le32(val);
		if (copy_to_user(buf + count - size, &val, 4))
			return -EFAULT;

		pos += 4;
		size -= 4;
	}

	while (size >= 2) {
		u16 val;

		ret = pci_user_read_config_word(pdev, pos, &val);
		if (ret)
			return pcibios_err_to_errno(ret);

		val = cpu_to_le16(val);
		if (copy_to_user(buf + count - size, &val, 2))
			return -EFAULT;

		pos += 2;
		size -= 2;
	}

	while (size) {
		u8 val;

		ret = pci_user_read_config_byte(pdev, pos, &val);
		if (ret)
			return pcibios_err_to_errno(ret);

		if (copy_to_user(buf + count - size, &val, 1))
			return -EFAULT;

		pos++;
		size--;
	}

	*ppos += count;

	return count;
}

static void vfio_pci_igd_cfg_release(struct vfio_pci_device *vdev,
				     struct vfio_pci_region *region)
{
	struct pci_dev *pdev = region->data;

	pci_dev_put(pdev);
}

static const struct vfio_pci_regops vfio_pci_igd_cfg_regops = {
	.rw		= vfio_pci_igd_cfg_rw,
	.release	= vfio_pci_igd_cfg_release,
};

static int vfio_pci_igd_cfg_init(struct vfio_pci_device *vdev)
{
	struct pci_dev *host_bridge, *lpc_bridge;
	int ret;

	host_bridge = pci_get_domain_bus_and_slot(0, 0, PCI_DEVFN(0, 0));
	if (!host_bridge)
		return -ENODEV;

	if (host_bridge->vendor != PCI_VENDOR_ID_INTEL ||
	    host_bridge->class != (PCI_CLASS_BRIDGE_HOST << 8)) {
		pci_dev_put(host_bridge);
		return -EINVAL;
	}

	ret = vfio_pci_register_dev_region(vdev,
		PCI_VENDOR_ID_INTEL | VFIO_REGION_TYPE_PCI_VENDOR_TYPE,
		VFIO_REGION_SUBTYPE_INTEL_IGD_HOST_CFG,
		&vfio_pci_igd_cfg_regops, host_bridge->cfg_size,
		VFIO_REGION_INFO_FLAG_READ, host_bridge);
	if (ret) {
		pci_dev_put(host_bridge);
		return ret;
	}

	lpc_bridge = pci_get_domain_bus_and_slot(0, 0, PCI_DEVFN(0x1f, 0));
	if (!lpc_bridge)
		return -ENODEV;

	if (lpc_bridge->vendor != PCI_VENDOR_ID_INTEL ||
	    lpc_bridge->class != (PCI_CLASS_BRIDGE_ISA << 8)) {
		pci_dev_put(lpc_bridge);
		return -EINVAL;
	}

	ret = vfio_pci_register_dev_region(vdev,
		PCI_VENDOR_ID_INTEL | VFIO_REGION_TYPE_PCI_VENDOR_TYPE,
		VFIO_REGION_SUBTYPE_INTEL_IGD_LPC_CFG,
		&vfio_pci_igd_cfg_regops, lpc_bridge->cfg_size,
		VFIO_REGION_INFO_FLAG_READ, lpc_bridge);
	if (ret) {
		pci_dev_put(lpc_bridge);
		return ret;
	}

	return 0;
}

/*
 * Zap mmaps on open so that we can fault them in on access and therefore
 * our vma_list only tracks mappings accessed since last zap.
 */
static void vfio_pci_igd_dsm_mmap_open(struct vm_area_struct *vma)
{
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
}

static vm_fault_t vfio_pci_igd_dsm_mmap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret = VM_FAULT_NOPAGE;

	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			    vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
		ret = VM_FAULT_SIGBUS;
	}

	return ret;
}

static const struct vm_operations_struct vfio_pci_igd_dsm_mmap_ops = {
	.open = vfio_pci_igd_dsm_mmap_open,
	.fault = vfio_pci_igd_dsm_mmap_fault,
};

static int vfio_pci_igd_dsm_mmap(struct vfio_pci_device *vdev,
				 struct vfio_pci_region *region,
				 struct vm_area_struct *vma)
{
	u64 req_len, pgoff, req_start;
	void *dsm_base = region->data;

	req_len = vma->vm_end - vma->vm_start;
	pgoff = vma->vm_pgoff &
		((1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	req_start = pgoff << PAGE_SHIFT;

	if (req_start + req_len > region->size)
		return -EINVAL;

	vma->vm_private_data = vdev;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = ((u64)dsm_base >> PAGE_SHIFT) + pgoff;

	/*
	 * See remap_pfn_range(), called from vfio_pci_fault() but we can't
	 * change vm_flags within the fault handler.  Set them now.
	 */
	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops = &vfio_pci_igd_dsm_mmap_ops;

	return 0;
}

static size_t vfio_pci_igd_dsm_rw(struct vfio_pci_device *vdev, char __user *buf,
			      size_t count, loff_t *ppos, bool iswrite)
{
	loff_t pos = *ppos & VFIO_PCI_OFFSET_MASK;

	if (pos != 0 || iswrite)
		return -EINVAL;

	if (copy_to_user(buf, &intel_graphics_stolen_res.start, 8))
		return -EFAULT;

	return 8;
}

static void vfio_pci_igd_dsm_release(struct vfio_pci_device *vdev,
				     struct vfio_pci_region *region)
{
}

static const struct vfio_pci_regops vfio_pci_igd_dsm_regops = {
	.rw		= vfio_pci_igd_dsm_rw,
	.mmap		= vfio_pci_igd_dsm_mmap,
	.release	= vfio_pci_igd_dsm_release,
};

static int vfio_pci_igd_dsm_init(struct vfio_pci_device *vdev)
{
	u16 gmch;
	u32 dsm_size;
	u64 dsm_base;
	int ret;

	pci_read_config_word(vdev->pdev, IGD_GMCH, &gmch);

	dsm_base = intel_graphics_stolen_res.start & ~((1024 * 1024) - 1); /* 1MB aligned */
	dsm_size = gen9_get_stolen_size(gmch);

	ret = vfio_pci_register_dev_region(vdev,
		PCI_VENDOR_ID_INTEL | VFIO_REGION_TYPE_PCI_VENDOR_TYPE,
		VFIO_REGION_SUBTYPE_INTEL_IGD_DSM,
		&vfio_pci_igd_dsm_regops, dsm_size,
		VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE | VFIO_REGION_INFO_FLAG_MMAP,
		(void *)dsm_base);

	return ret;
}

int vfio_pci_igd_init(struct vfio_pci_device *vdev)
{
	int ret;

	ret = vfio_pci_igd_opregion_init(vdev);
	if (ret)
		return ret;

	ret = vfio_pci_igd_cfg_init(vdev);
	if (ret)
		return ret;

	ret = vfio_pci_igd_dsm_init(vdev);
	if (ret)
		return ret;

	return 0;
}
