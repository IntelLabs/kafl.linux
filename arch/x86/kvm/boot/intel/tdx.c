// SPDX-License-Identifier: GPL-2.0
#include <linux/earlycpio.h>
#include <linux/fs.h>
#include <linux/percpu.h>
#include <linux/memblock.h>
#include <linux/idr.h>

#include <asm/cpu.h>
#include <asm/kvm_boot.h>
#include <asm/virtext.h>
#include <asm/tlbflush.h>
#include <asm/e820/api.h>

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

/*
 * Define __seamcall used by boot code to override the default in tdx_ops.h.
 * The default BUG()s on faults, which is undesirable during boot, and calls
 * kvm_spurious_fault(), which isn't linkable if KVM is built as a module.
 * RAX contains '0' on success, TDX-SEAM errno on failure, vector on fault.
 */
#define seamcall ".byte 0x66,0x0f,0x01,0xcf"

#define __seamcall			\
	"1:" seamcall "\n\t"		\
	"2: \n\t"			\
	_ASM_EXTABLE_FAULT(1b, 2b)

#include "intel/tdx_arch.h"
#include "intel/tdx_ops.h"
#include "intel/tdx_errno.h"

#include "intel/vmcs.h"

/*
 * TODO: better to have kernel boot parameter to let admin control whether to
 * enable TDX with sysprof or not.
 *
 * Or how to decide tdx_sysprof??
 */
static bool tdx_sysprof;

/* KeyID range reserved to TDX by BIOS */
static u32 tdx_keyids_start;
static u32 tdx_nr_keyids;

/* TDX keyID pool */
static DEFINE_IDA(tdx_keyid_pool);

/* CPU mask for TDSYSCONFIGKEY/TDCONFIGKEY -- one cpu per package. */
static struct cpumask __tdx_package_leadcpus __ro_after_init;
const struct cpumask *tdx_package_leadcpus = &__tdx_package_leadcpus;
EXPORT_SYMBOL_GPL(tdx_package_leadcpus);

/*
 * TDX system information returned by TDSYSINFO.
 */
static struct tdsysinfo_struct tdx_tdsysinfo __aligned(1024);

/*
 * CMR info array returned by TDSYSINFO.
 *
 * TDSYSINFO doesn't return specific error code indicating whether we didn't
 * pass long-enough CMR info array to it, so just reserve enough space for
 * the maximum number of CMRs.
 */
static struct cmr_info tdx_cmrs[TDX1_MAX_NR_CMRS] __aligned(512);
static int tdx_nr_cmrs;

/*
 * TDMR info array used as input for TDSYSCONFIG.
 */
static struct tdmr_info tdx_tdmrs[TDX1_MAX_NR_TDMRS] __initdata;
static int tdx_nr_tdmrs __initdata;

/* TDMRs must be 1gb aligned */
#define TDMR_ALIGNMENT		BIT_ULL(30)
#define TDMR_PFN_ALIGNMENT	(TDMR_ALIGNMENT >> PAGE_SHIFT)

/*
 * TDSYSCONFIG takes a array of pointers to TDMR infos.  Its just big enough
 * that allocating it on the stack is undesirable.
 */
static u64 tdx_tdmr_addrs[TDX1_MAX_NR_TDMRS] __aligned(512) __initdata;

struct pamt_info {
	u64 pamt_base;
	u64 pamt_size;
};

/*
 * PAMT info for each TDMR, used to free PAMT when TDX is disabled due to
 * whatever reason.
 */
static struct pamt_info tdx_pamts[TDX1_MAX_NR_TDMRS] __initdata;

static int __init set_tdmr_reserved_area(struct tdmr_info *tdmr, int *p_idx,
					 u64 offset, u64 size)
{
	int idx = *p_idx;

	if (idx >= tdx_tdsysinfo.max_reserved_per_tdmr)
		return -EINVAL;

	/* offset & size must be 4K aligned */
	if (offset & ~PAGE_MASK || size & ~PAGE_MASK)
		return -EINVAL;

	tdmr->reserved_areas[idx].offset = offset;
	tdmr->reserved_areas[idx].size = size;

	*p_idx = idx + 1;
	return 0;
}

/*
 * Construct TDMR reserved areas.
 *
 * Two types of address range will be put into reserved areas: 1) PAMT range,
 * since PAMT cannot overlap with TDMR non-reserved range; 2) any CMR hole
 * within TDMR range, since TDMR non-reserved range must be in CMR.
 *
 * Note: we are not putting any memory hole made by kernel (which is not CMR
 * hole -- i.e. some memory range is reserved by kernel and won't be freed to
 * page allocator, and it is memory hole from page allocator's view) into
 * reserved area for the sake of simplicity of implementation. The other
 * reason is for TDX1 one TDMR can only have upto 16 reserved areas so if
 * there are lots of holes we won't be have enough reserved areas to hold
 * them. This is OK, since kernel page allocator will never allocate pages
 * from those areas (as they are invalid). PAMT may internally mark them as
 * 'normal' pages but it is OK.
 *
 * Returns -EINVAL if number of reserved areas exceeds TDX1 limitation.
 *
 */
static int __init __construct_tdmr_reserved_areas(struct tdmr_info *tdmr,
						  u64 pamt_base, u64 pamt_size)
{
	u64 tdmr_start, tdmr_end, offset, size;
	struct cmr_info *cmr, *next_cmr;
	bool pamt_done = false;
	int i, idx, ret;

	memset(tdmr->reserved_areas, 0, sizeof(tdmr->reserved_areas));

	/* Save some typing later */
	tdmr_start = tdmr->base;
	tdmr_end = tdmr->base + tdmr->size;

	if (WARN_ON(!tdx_nr_cmrs))
		return -EINVAL;
	/*
	 * Find the first CMR whose end is greater than tdmr_start_pfn.
	 */
	cmr = &tdx_cmrs[0];
	for (i = 0; i < tdx_nr_cmrs; i++) {
		cmr = &tdx_cmrs[i];
		if ((cmr->base + cmr->size) > tdmr_start)
			break;
	}

	/* Unable to find ?? Something is wrong here */
	if (i == tdx_nr_cmrs)
		return -EINVAL;

	/*
	 * If CMR base is within TDMR range, [tdmr_start, cmr->base) needs to be
	 * in reserved area.
	 */
	idx = 0;
	if (cmr->base > tdmr_start) {
		offset = 0;
		size = cmr->base - tdmr_start;

		ret = set_tdmr_reserved_area(tdmr, &idx, offset, size);
		if (ret)
			return ret;
	}

	/*
	 * Check whether there's any hole between CMRs within TDMR range.
	 * If there is any, it needs to be in reserved area.
	 */
	for (++i; i < tdx_nr_cmrs; i++) {
		next_cmr = &tdx_cmrs[i];

		/*
		 * If next CMR is beyond TDMR range, there's no CMR hole within
		 * TDMR range, and we only need to insert PAMT into reserved
		 * area, thus  we are done here.
		 */
		if (next_cmr->base >= tdmr_end)
			break;

		/* Otherwise need to have CMR hole in reserved area */
		if (cmr->base + cmr->size < next_cmr->base) {
			offset = cmr->base + cmr->size - tdmr_start;
			size = next_cmr->base - (cmr->base + cmr->size);

			/*
			 * Reserved areas needs to be in physical address
			 * ascending order, therefore we need to check PAMT
			 * range before filling any CMR hole into reserved
			 * area.
			 */
			if (pamt_base < tdmr_start + offset) {
				/*
				 * PAMT won't overlap with any CMR hole
				 * otherwise there's bug -- see comments below.
				 */
				if (WARN_ON((pamt_base + pamt_size) >
					    (tdmr_start + offset)))
					return -EINVAL;

				ret = set_tdmr_reserved_area(tdmr, &idx,
							     pamt_base - tdmr_start,
							     pamt_size);
				if (ret)
					return ret;

				pamt_done = true;
			}

			/* Insert CMR hole into reserved area */
			ret = set_tdmr_reserved_area(tdmr, &idx, offset, size);
			if (ret)
				return ret;
		}

		cmr = next_cmr;
	}

	if (!pamt_done) {
		/*
		 * PAMT won't overlap with CMR range, otherwise there's bug
		 * -- we have guaranteed this by checking all CMRs have
		 * covered all memory in e820.
		 */
		if (WARN_ON((pamt_base + pamt_size) > (cmr->base + cmr->size)))
			return -EINVAL;

		ret = set_tdmr_reserved_area(tdmr, &idx,
					     pamt_base - tdmr_start, pamt_size);
		if (ret)
			return ret;
	}

	/*
	 * If CMR end is in TDMR range, [cmr->end, tdmr_end) needs to be in
	 * reserved area.
	 */
	if (cmr->base + cmr->size < tdmr_end) {
		offset = cmr->base + cmr->size - tdmr_start;
		size = tdmr_end - (cmr->base + cmr->size);

		ret = set_tdmr_reserved_area(tdmr, &idx, offset, size);
		if (ret)
			return ret;
	}

	return 0;
}

static int __init __construct_tdmr_node(int tdmr_idx,
					unsigned long tdmr_start_pfn,
					unsigned long tdmr_end_pfn)
{
	u64 tdmr_size, pamt_1g_size, pamt_2m_size, pamt_4k_size, pamt_size;
	struct pamt_info *pamt = &tdx_pamts[tdmr_idx];
	struct tdmr_info *tdmr = &tdx_tdmrs[tdmr_idx];
	u64 pamt_phys;
	int ret;

	tdmr_size = (tdmr_end_pfn - tdmr_start_pfn) << PAGE_SHIFT;

	/* sanity check */
	if (!tdmr_size || !IS_ALIGNED(tdmr_size, TDMR_ALIGNMENT))
		return -EINVAL;

	/* 1 entry to cover 1G */
	pamt_1g_size = (tdmr_size >> 30) * tdx_tdsysinfo.pamt_entry_size;
	/* 1 entry to cover 2M */
	pamt_2m_size = (tdmr_size >> 21) * tdx_tdsysinfo.pamt_entry_size;
	/* 1 entry to cover 4K */
	pamt_4k_size = (tdmr_size >> 12) * tdx_tdsysinfo.pamt_entry_size;

	pamt_size = ALIGN(pamt_1g_size, PAGE_SIZE) +
		    ALIGN(pamt_2m_size, PAGE_SIZE) +
		    ALIGN(pamt_4k_size, PAGE_SIZE);

	pamt_phys = memblock_phys_alloc_range(pamt_size, PAGE_SIZE,
					      tdmr_start_pfn << PAGE_SHIFT,
					      tdmr_end_pfn << PAGE_SHIFT);
	if (!pamt_phys)
		return -ENOMEM;

	tdmr->base = tdmr_start_pfn << PAGE_SHIFT;
	tdmr->size = tdmr_size;

	/* PAMT for 1G at first */
	tdmr->pamt_1g_base = pamt_phys;
	tdmr->pamt_1g_size = ALIGN(pamt_1g_size, PAGE_SIZE);
	/* PAMT for 2M right after PAMT for 1G */
	tdmr->pamt_2m_base = tdmr->pamt_1g_base + tdmr->pamt_1g_size;
	tdmr->pamt_2m_size = ALIGN(pamt_2m_size, PAGE_SIZE);
	/* PAMT for 4K comes after PAMT for 2M */
	tdmr->pamt_4k_base = tdmr->pamt_2m_base + tdmr->pamt_2m_size;
	tdmr->pamt_4k_size = ALIGN(pamt_4k_size, PAGE_SIZE);

	/* Construct TDMR's reserved areas */
	ret = __construct_tdmr_reserved_areas(tdmr, tdmr->pamt_1g_base,
					      pamt_size);
	if (ret) {
		memblock_free(pamt_phys, pamt_size);
		return ret;
	}

	/* Record PAMT info for this TDMR */
	pamt->pamt_base = pamt_phys;
	pamt->pamt_size = pamt_size;

	return 0;
}

/*
 * Convert node's memory into TDMRs as less as possible.
 *
 * @node_start_pfn and @node_end_pfn are not node's real memory region, but
 * already 1G aligned passed from caller.
 */
static int __init construct_tdmr_node(int *p_tdmr_idx,
				      unsigned long tdmr_start_pfn,
				      unsigned long tdmr_end_pfn)
{
	u64 start_pfn, end_pfn, mid_pfn;
	int ret = 0, idx = *p_tdmr_idx;

	start_pfn = tdmr_start_pfn;
	end_pfn = tdmr_end_pfn;

	while (start_pfn < tdmr_end_pfn) {
		/* Cast to u32, else compiler will sign extend and complain. */
		if (idx >= (u32)tdx_tdsysinfo.max_tdmrs)
			return -EINVAL;

		ret = __construct_tdmr_node(idx, start_pfn, end_pfn);

		/*
		 * Try again with smaller TDMR if the failure was due to unable
		 * to allocate PAMT.
		 */
		if (ret == -ENOMEM) {
			mid_pfn = start_pfn + (end_pfn - start_pfn) / 2;
			mid_pfn = ALIGN_DOWN(mid_pfn, TDMR_PFN_ALIGNMENT);
			end_pfn = mid_pfn;
			continue;
		} else if (ret) {
			return ret;
		}

		/* Successfully done with one TDMR, and continue if there's remaining */
		start_pfn = end_pfn;
		end_pfn = tdmr_end_pfn;
		idx++;
	}

	/* Setup next TDMR entry to work on */
	*p_tdmr_idx = idx;
	return ret;
}

/*
 * Construct TDMR based on system memory info and CMR info. To avoid modifying
 * kernel core-mm page allocator to have TDMR specific logic for memory
 * allocation in TDMR, we choose to simply convert all memory to TDMR, with the
 * disadvantage of wasting some memory for PAMT, but since TDX is mainly a
 * virtualization feature so it is expected majority of memory will be used as
 * TD guest memory so wasting some memory for PAMT won't be big issue.
 *
 * There are some restrictions of TDMR/PAMT/CMR:
 *
 *  - TDMR's base and size need to be 1G aligned.
 *  - TDMR's size need to be multiple of 1G.
 *  - TDMRs cannot overlap with each other.
 *  - PAMTs cannot overlap with each other.
 *  - Each TDMR can have reserved areas (TDX1 upto 16).
 *  - TDMR reserved areas must be in physical address ascending order.
 *  - TDMR non-reserved area must be in CMR.
 *  - TDMR reserved area doesn't have to be in CMR.
 *  - TDMR non-reserved area cannot overlap with PAMT.
 *  - PAMT may reside within TDMR reserved area.
 *  - PAMT must be in CMR.
 *
 */
static int __init __construct_tdmrs(void)
{
	u64 tdmr_start_pfn, tdmr_end_pfn, tdmr_start_pfn_next;
	unsigned long start_pfn, end_pfn;
	int last_nid, nid, i, idx, ret;

	/* Sanity check on tdx_tdsysinfo... */
	if (!tdx_tdsysinfo.max_tdmrs || !tdx_tdsysinfo.max_reserved_per_tdmr ||
	    !tdx_tdsysinfo.pamt_entry_size) {
		pr_err("Invalid TDSYSINFO_STRUCT reported by TDSYSINFO.\n");
		return -ENOTSUPP;
	}

	idx = 0;
	tdmr_start_pfn = 0;
	tdmr_end_pfn = 0;
	last_nid = MAX_NUMNODES;
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
		if (last_nid == MAX_NUMNODES) {
			/* First memory range */
			last_nid = nid;
			tdmr_start_pfn = ALIGN_DOWN(start_pfn, TDMR_PFN_ALIGNMENT);
			WARN_ON(tdmr_start_pfn != 0);
		} else if (nid == last_nid) {
			/*
			 * This memory range is in the same node as previous
			 * one, update tdmr_end_pfn.
			 */
			tdmr_end_pfn = ALIGN(end_pfn, TDMR_PFN_ALIGNMENT);
		} else if (ALIGN(start_pfn, TDMR_PFN_ALIGNMENT) >= tdmr_end_pfn) {
			/* This memory range is in next node */
			tdmr_start_pfn_next = ALIGN(start_pfn, TDMR_PFN_ALIGNMENT);

			/*
			 * If new TDMR start pfn is greater than previous TDMR
			 * end pfn, then it's ready to convert previous node's
			 * memory to TDMR.
			 */
			ret = construct_tdmr_node(&idx, tdmr_start_pfn,
						  tdmr_end_pfn);
			if (ret)
				return ret;
		} else {
			/*
			 * This memory range is in the next node, and the
			 * boundary between nodes falls into 1G range.  In this
			 * case, put the end of the first node and start of the
			 * second node into a single TDMR.
			 */
			tdmr_start_pfn_next = ALIGN(start_pfn, TDMR_PFN_ALIGNMENT);

			ret = construct_tdmr_node(&idx,
						  tdmr_start_pfn_next,
						  tdmr_end_pfn);
			if (ret)
				return ret;

			tdmr_start_pfn_next = ALIGN(start_pfn, TDMR_PFN_ALIGNMENT);
			tdmr_start_pfn = tdmr_start_pfn_next;
			tdmr_end_pfn = tdmr_start_pfn;
			last_nid = nid;
		}
	}

	ret = construct_tdmr_node(&idx, tdmr_start_pfn, tdmr_end_pfn);
	if (ret)
		return ret;

	tdx_nr_tdmrs = idx;

	return 0;
}

static int __init e820_type_cmr_ram(enum e820_type type)
{
	/*
	 * CMR needs to at least cover e820 memory regions which will be later
	 * freed to kernel memory allocator, otherwise kernel may allocate
	 * non-TDMR pages, i.e. when KVM allocates memory.
	 *
	 * Note memblock also treats E820_TYPE_RESERVED_KERN as memory so also
	 * need to cover it.
	 *
	 * FIXME:
	 *
	 * Need to cover other types which are actually RAM, i.e:
	 *
	 *   E820_TYPE_ACPI,
	 *   E820_TYPE_NVS
	 */
	return (type == E820_TYPE_RAM || type == E820_TYPE_RESERVED_KERN);
}

static int __init in_cmr_range(u64 addr, u64 size)
{
	struct cmr_info *cmr;
	u64 cmr_end, end;
	int i;

	end = addr + size;

	/* Ignore bad area */
	if (end < addr)
		return 1;

	for (i = 0; i < tdx_nr_cmrs; i++) {
		cmr = &tdx_cmrs[i];
		cmr_end = cmr->base + cmr->size;

		/* Found one CMR which covers the range [addr, addr + size) */
		if (cmr->base <= addr && cmr_end >= end)
			return 1;
	}

	return 0;
}

static int __init sanity_check_cmrs(void)
{
	struct e820_entry *entry;
	int i;

	/*
	 * FIXME: faked-seamldr only??
	 *
	 * On faked-seamldr I observed that TDSYSINFO always return 32 CMRs even
	 * only two CMRs are actually valid, and others are all with both base
	 * and size as 0.  Adjust tdx_nr_cmrs to remove those invalid CMRs.
	 */
	for (i = 0; i < tdx_nr_cmrs; i++) {
		if (!tdx_cmrs[i].size)
			break;
	}
	tdx_nr_cmrs = i;
	if (!tdx_nr_cmrs)
		return -EINVAL;

	/*
	 * Sanity check whether CMR has covered all memory in E820. We need
	 * to make sure that CMR covers all memory that will be freed to page
	 * allocator, otherwise alloc_pages() may return non-TDMR pages, i.e.
	 * when KVM allocates memory for VM. Cannot allow that to happen, so
	 * disable TDX if we found CMR doesn't cover all.
	 *
	 * FIXME:
	 *
	 * Alternatively we could just check against memblocks? Only memblocks
	 * are freed to page allocator so it appears to be OK as long as CMR
	 * covers all memblocks. But CMR should be generated by BIOS thus should
	 * be cover e820..
	 */
	for (i = 0; i < e820_table->nr_entries; i++) {
		entry = &e820_table->entries[i];

		if (!e820_type_cmr_ram(entry->type))
			continue;

		if (!in_cmr_range(entry->addr, entry->size))
			return -EINVAL;
	}

	return 0;
}

static int __init construct_tdmrs(void)
{
	struct pamt_info *pamt;
	int ret, i;

	ret = sanity_check_cmrs();
	if (ret)
		return ret;

	ret = __construct_tdmrs();
	if (ret)
		goto free_pamts;
	return 0;

free_pamts:
	for (i = 0; i < ARRAY_SIZE(tdx_pamts); i++) {
		pamt = &tdx_pamts[i];
		if (pamt->pamt_base && pamt->pamt_size) {
			if (WARN_ON(!IS_ALIGNED(pamt->pamt_base, PAGE_SIZE) ||
				    !IS_ALIGNED(pamt->pamt_size, PAGE_SIZE)))
				continue;

			memblock_free(pamt->pamt_base, pamt->pamt_size);
		}
	}

	memset(tdx_pamts, 0, sizeof(tdx_pamts));
	memset(tdx_tdmrs, 0, sizeof(tdx_tdmrs));
	tdx_nr_tdmrs = 0;
	return ret;
}


/*
 * Well.. I guess a better way is to put cpu_vmxon() into asm/virtext.h,
 * and split kvm_cpu_vmxon() into cpu_vmxon(), and intel_pt_handle_vmx(),
 * so we just only have one cpu_vmxon() in asm/virtext.h..
 */
static inline void cpu_vmxon(u64 vmxon_region)
{
	cr4_set_bits(X86_CR4_VMXE);
	asm volatile ("vmxon %0" : : "m"(vmxon_region));
}

static inline int tdx_vmxon(struct vmcs *vmcs)
{
	u64 msr;

	/*
	 * Can't enable TDX if VMX is unsupported or disabled by BIOS.
	 * cpu_has(X86_FEATURE_VMX) can't be relied on as the BSP calls this
	 * before the kernel has configured feat_ctl().
	 */
	if (!cpu_has_vmx())
		return -ENOTSUPP;

	if (rdmsrl_safe(MSR_IA32_FEAT_CTL, &msr) ||
	    !(msr & FEAT_CTL_LOCKED) ||
	    !(msr & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX))
		return -ENOTSUPP;

	if (rdmsrl_safe(MSR_IA32_VMX_BASIC, &msr))
		return -ENOTSUPP;

	memset(vmcs, 0, PAGE_SIZE);
	vmcs->hdr.revision_id = (u32)msr;

	cpu_vmxon(__pa(vmcs));

	return 0;
}

static int __tdx_init_cpu(struct cpuinfo_x86 *c, unsigned long vmcs)
{
	bool is_bsp = (c == &boot_cpu_data);
	u32 mktme_keyids, tdx_keyids;
	struct tdx_ex_ret ex_ret;
	u64 err;
	int ret;

	/*
	 * Detect HKID for TDX if initialization was successful.
	 *
	 * TDX provides core-scoped MSR for us to simply read out TDX start
	 * keyID and number of keyIDs. It seems we don't need to calculate
	 * manually from MSR_IA32_TME_ACTIVATE.
	 *
	 * Because it is core-scoped, we'd better read out for each core,
	 * and disable TDX if value mismatches between any two cores.
	 */
	rdmsr(MSR_IA32_MKTME_KEYID_PART, mktme_keyids, tdx_keyids);
	if (!mktme_keyids || (tdx_keyids < 2))
		return -ENOTSUPP;

	ret = tdx_vmxon((void *)vmcs);
	if (ret)
		return ret;

	/* For BSP, call TDSYSINIT first for platform-level initialization. */
	if (is_bsp) {
		tdx_keyids_start = mktme_keyids;
		tdx_nr_keyids = tdx_keyids;

		err = tdsysinit(tdx_sysprof ? BIT(0) : 0, &ex_ret);
		if (TDX_ERR(err, TDSYSINIT)) {
			ret = -EIO;
			goto out;
		}
	} else if (mktme_keyids != tdx_keyids_start ||
		   tdx_keyids != tdx_nr_keyids) {
		pr_err("MSR_IA32_MKTME_KEYID_PART value inconsistent among cpus.\n");
		ret = -EINVAL;
		goto out;
	}

	/* Call TDSYSINITLP for per-cpu initialization */
	err = tdsysinitlp(&ex_ret);
	if (TDX_ERR(err, TDSYSINITLP)) {
		ret = -EIO;
		goto out;
	}

	/*
	 * Call TDSYSINFO right after TDSYSINITTLP on BSP, since constructing
	 * TDMRs needs to be done before kernel page allocator is up (which
	 * means before SMP is up), because it requires to reserve large chunk
	 * of memory (>4MB) which kernel page allocator cannot allocate, and
	 * reserving PAMT requires info returned by TDSYSINFO.
	 */
	if (is_bsp) {
		err = tdsysinfo(__pa(&tdx_tdsysinfo), sizeof(tdx_tdsysinfo),
				__pa(tdx_cmrs), TDX1_MAX_NR_CMRS, &ex_ret);
		if (TDX_ERR(err, TDSYSINFO)) {
			ret = -EIO;
			goto out;
		}

		tdx_nr_cmrs = ex_ret.nr_cmr_entries;
	}
out:
	cpu_vmxoff();

	return ret;
}

void tdx_init_cpu(struct cpuinfo_x86 *c)
{
	unsigned long vmcs;

	/* BSP does TDSYSINITLP as part of tdx_seam_init(). */
	if (c == &boot_cpu_data)
		return;

	/* Allocate VMCS for VMXON. */
	vmcs = __get_free_page(GFP_KERNEL);
	if (!vmcs) {
		clear_cpu_cap(c, X86_FEATURE_TDX);
		return;
	}

	/* VMXON and TDSYSINITLP shouldn't fail at this point. */
	if (WARN_ON_ONCE(__tdx_init_cpu(c, vmcs)))
		clear_cpu_cap(c, X86_FEATURE_TDX);

	free_page(vmcs);
}

void __init tdx_seam_init(void)
{
	const char *sigstruct_name = "intel-seam/libtdx.so.sigstruct";
	const char *seamldr_name = "intel-seam/seamldr.acm";
	const char *module_name = "intel-seam/libtdx.so";
	struct cpio_data module, sigstruct, seamldr;
	void *vmcs;

	/* The VMM may have preloaded a module when running as a VM. */
	if (boot_cpu_has(X86_FEATURE_HYPERVISOR) && is_seam_module_loaded()) {
		pr_info("using preloaded SEAM module\n");
		goto init_seam;
	}

        if (!get_builtin_firmware(&module, module_name))
                return;

	/* Use the kernel's fake SEAMLDR when running as a VM. */
        if (boot_cpu_has(X86_FEATURE_HYPERVISOR)) {
                if (seam_load_module(module_name, module.data, module.size))
			return;
	} else {
		if (!get_builtin_firmware(&sigstruct, sigstruct_name))
			return;

		if (!get_builtin_firmware(&seamldr, seamldr_name))
			return;

		/* TODO: invoke GETSEC to run real SEAMLDR. */
	}

init_seam:
	vmcs = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
	if (!vmcs)
		return;

	if (!__tdx_init_cpu(&boot_cpu_data, (unsigned long)vmcs))
		setup_force_cpu_cap(X86_FEATURE_TDX);

	/*
	 * Free VMCS here, since it's harder to free it later, i.e after SMP
	 * is up, because at that time page allocator is already up. VMCS can
	 * be allocated again when needed before TDSYSCONFIG staff.
	 */
	memblock_free(__pa(vmcs), PAGE_SIZE);

	if (construct_tdmrs())
		goto error;

	return;

error:
	clear_cpu_cap(&boot_cpu_data, X86_FEATURE_TDX);
	setup_clear_cpu_cap(X86_FEATURE_TDX);
}

/*
 * Setup one-cpu-per-pkg cpumask. TDSYSCONFIGKEY is per-pkg and needs to be
 * done on all pkgs. The cpumask is also exposed for KVM since TDCONFIGKEY
 * is also per-pkg and needs it.
 */
static int __init init_package_cpumask(void)
{

	unsigned long *tdx_package_bitmap;
	int cpu, target_id;

	cpumask_clear(&__tdx_package_leadcpus);

	tdx_package_bitmap = bitmap_zalloc(topology_max_packages(), GFP_KERNEL);
	if (!tdx_package_bitmap)
		return -ENOMEM;

	for_each_online_cpu(cpu) {
		target_id = topology_physical_package_id(cpu);
		if (!__test_and_set_bit(target_id, tdx_package_bitmap))
			__cpumask_set_cpu(cpu, &__tdx_package_leadcpus);
	}

	bitmap_free(tdx_package_bitmap);

	return 0;
}

static int __init __do_tdsysconfigkey(void)
{
	bool need_vmxon = !(cr4_read_shadow() & X86_CR4_VMXE);
	unsigned long uninitialized_var(vmcs);
	u64 err;

	if (need_vmxon) {
		vmcs = __get_free_page(GFP_KERNEL);
		if (!vmcs)
			return -ENOMEM;
		tdx_vmxon((void *)vmcs);
	}

	err = tdsysconfigkey();
	TDX_ERR(err, TDSYSCONFIGKEY);

	if (need_vmxon) {
		cpu_vmxoff();
		free_page(vmcs);
	}

	return err ? -EIO : 0;
}

static void __init do_tdsysconfigkey(void *err)
{
	int ret = __do_tdsysconfigkey();

	if (ret)
		*(int *)err = ret;
}

static int __init tdx_init_tdmr(void)
{
	struct tdx_ex_ret ex_ret;
	u64 base, size;
	u64 err;
	int i;

	for (i = 0; i < tdx_nr_tdmrs; i++) {
		base = tdx_tdmrs[i].base;
		size = tdx_tdmrs[i].size;

		do {
			err = tdsysinittdmr(base, &ex_ret);
			if (TDX_ERR(err, TDSYSINITTDMR))
				return -EIO;
		/*
		 * Note, "next" is simply an indicator, base is passed to
		 * TDSYSINTTDMR on every iteration.
		 */
		} while (ex_ret.next < (base + size));
	}

	return 0;
}

static int __init tdx_init(void)
{
	unsigned long vmcs;
	int ret, i;
	u64 err;

	if (!boot_cpu_has(X86_FEATURE_TDX))
		return -ENOTSUPP;

	ret = init_package_cpumask();
	if (ret)
		goto err;

	vmcs = __get_free_page(GFP_KERNEL);
	if (!vmcs) {
		ret = -ENOMEM;
		goto err;
	}

	ret = tdx_vmxon((void *)vmcs);
	if (ret)
		goto free_vmcs;

	for (i = 0; i < tdx_nr_tdmrs; i++)
		tdx_tdmr_addrs[i] = __pa(&tdx_tdmrs[i]);

	/* Use the first keyID as TDX-SEAM's global key. */
	err = tdsysconfig(__pa(tdx_tdmr_addrs), tdx_nr_tdmrs, tdx_keyids_start);
	if (TDX_ERR(err, TDSYSCONFIG)) {
		ret = -EIO;
		goto vmxoff;
	}

	on_each_cpu_mask(tdx_package_leadcpus, do_tdsysconfigkey, &ret, true);
	if (ret)
		goto vmxoff;

	ret = tdx_init_tdmr();
	if (ret)
		goto vmxoff;

vmxoff:
	cpu_vmxoff();

free_vmcs:
	free_page(vmcs);
	if (ret)
		goto err;

	pr_info("TDX initialized.\n");

	return 0;

err:
	clear_cpu_cap(&boot_cpu_data, X86_FEATURE_TDX);
	return ret;
}
arch_initcall(tdx_init);

struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	if (boot_cpu_has(X86_FEATURE_TDX))
		return &tdx_tdsysinfo;

	return NULL;
}
EXPORT_SYMBOL_GPL(tdx_get_sysinfo);

int tdx_keyid_alloc(void)
{
	if (!boot_cpu_has(X86_FEATURE_TDX))
		return -EINVAL;

	if (WARN_ON_ONCE(!tdx_keyids_start || !tdx_nr_keyids))
		return -EINVAL;

	/* The first keyID is reserved for the global key. */
	return ida_alloc_range(&tdx_keyid_pool, tdx_keyids_start + 1,
			       tdx_keyids_start + tdx_nr_keyids - 2,
			       GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(tdx_keyid_alloc);

void tdx_keyid_free(int keyid)
{
	if (!keyid || keyid < 0)
		return;

	ida_free(&tdx_keyid_pool, keyid);
}
EXPORT_SYMBOL_GPL(tdx_keyid_free);
