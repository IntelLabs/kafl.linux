// SPDX-License-Identifier: GPL-2.0
#include <linux/elf.h>
#include <linux/io.h>
#include <linux/fs.h>

#include <asm/kvm_boot.h>
#include <asm/page_types.h>
#include <asm/pgtable_types.h>

#undef pr_fmt
#define pr_fmt(fmt) "seamldr: " fmt

static void	*seam_va;
static u64	seam_base;
static u64	seam_rip_offset;

struct seam_mmu {
	u64	root_pa;	 /* PA of paging root, a.k.a. cr3 */
	u64	next_pa;	/* Rudimentary memory allocator, grows down. */
	u64	nr_page_levels;	/* 4 or 5 level paging */
};

struct seam_region {
	u64	base;	/* Base virtual address of the region. */
	u64	size;	/* Size of the region, in bytes. */
};

#define SEAM_MAX_PKGS   8
#define SEAM_MAX_CMRS   32

struct seam_sysinfo
{
	/* Fields populated by MCHECK */
	u64 version;				   /**< Structure Version – Set to 0 */
	u32 nr_lps;					/**< Total number of logical processors in platform */
	u32 nr_sockets;				/**< Total number of sockets in platform */
	u32 socket_fms[SEAM_MAX_PKGS]; /**< List of CPUID.leaf_1.EAX values from all sockets */
	u8 reserved_0[80];			 /**< Reserved */
	struct seam_region cmr[SEAM_MAX_CMRS];	/**< CMR info (base and size) */
	u8 reserved_1[1408];		   /**< Reserved */

	/* Fields initialized to zero by MCHECK and populated by SEAMLDR ACM */
	u64 seam_status;			   /**< SEAM status */
										/**< 0: NOT_LOADED   - module not loaded */
										/**< 1: LOADED	   - module load complete */
										/**< 2: LOAD_IN_PROG - module load in progress */
	struct seam_region code;
	struct seam_region data;
	struct seam_region stack;
	struct seam_region keyhole;
	struct seam_region keyhole_edit;
	u64 num_stack_pages;		   /**< Data Stack size per LP unit=(# 4K pages) – 1 */
	u64 num_tls_pages;			 /**< TLS size per LP - unit=(# 4K pages) – 1 */
	u8 reserved_2[1944];		   /**< Reserved */
};

/* Hardcoded virtual addresses for TDX-SEAM. */
#define SEAM_KEYHOLE_EDIT_BASE	0x0000000100000000ull
#define SEAM_CODE_BASE		0xFFFF800000000000ull
#define SEAM_STACK_BASE		0xFFFF800100000000ull
#define SEAM_KEYHOLE_BASE	0xFFFF800200000000ull
#define SEAM_DATA_BASE		0xFFFF800300000000ull
#define SEAM_SYS_INFO_BASE	0xFFFF8003FFFF0000ull

/* Hardcoded sizes of select regions for TDX-SEAM. */
#define SEAM_PER_LP_STACK_SIZE		(16 * PAGE_SIZE)
#define SEAM_PER_LP_SHADOW_STACK_SIZE	(1 * PAGE_SIZE)
#define SEAM_PER_LP_TLS_SIZE		(2 * PAGE_SIZE)
#define SEAM_PER_LP_KEYHOLE_SIZE	(128 * PAGE_SIZE)

#define KiB              (1 * 1024)
#define MiB            (KiB * 1024)
#define GiB            (MiB * 1024)

#define SEAM_SIZE			(128 * MiB)
#define SEAM_CODE_SIZE			(2 * MiB)

#define PXE_MASK(x)	BIT(_PAGE_BIT_##x)

#define SEAM_SYSINFO_ATTR	(PXE_MASK(PRESENT) | PXE_MASK(ACCESSED) | PXE_MASK(NX))
#define SEAM_CODE_ATTR		(PXE_MASK(PRESENT))
#define SEAM_PXE_ATTR		(PXE_MASK(PRESENT) | PXE_MASK(RW) | PXE_MASK(ACCESSED))
#define SEAM_DATA_ATTR		(PXE_MASK(PRESENT) | PXE_MASK(RW) | PXE_MASK(ACCESSED) | PXE_MASK(DIRTY) | PXE_MASK(NX))
#define SEAM_STACK_ATTR		(PXE_MASK(PRESENT) | PXE_MASK(RW) | PXE_MASK(ACCESSED) | PXE_MASK(DIRTY) | PXE_MASK(NX))
#define SEAM_SHADOW_STACK_ATTR	(PXE_MASK(PRESENT) | PXE_MASK(ACCESSED) | PXE_MASK(DIRTY) | PXE_MASK(NX))
#define SEAM_KEYHOLE_EDIT_ATTR	(PXE_MASK(PRESENT) | PXE_MASK(RW) | PXE_MASK(ACCESSED) | PXE_MASK(DIRTY) | PXE_MASK(NX) | PXE_MASK(USER))

#define MSR_IA32_SEAMRR_BASE_SDV	0x0000013e

#define seam_pa_to_va(pa)	 (void *)((pa) - seam_base + (u64)seam_va)

static u64 seam_sys_info_pa(void)
{
	return seam_base;
}

static u64 seam_vmcs_base_pa(void)
{
	return seam_base + PAGE_SIZE;
}

static u64 seam_code_base_pa(void)
{
	return seam_base + SEAM_SIZE - SEAM_CODE_SIZE;
}

static u64 seam_data_base_pa(u32 nr_lps)
{
	return seam_base + ((nr_lps + 1) * PAGE_SIZE);
}

static u64 seam_stack_base_pa(u32 nr_lps)
{
	return seam_code_base_pa() -
			(nr_lps * (SEAM_PER_LP_STACK_SIZE + SEAM_PER_LP_SHADOW_STACK_SIZE));
}

static u64 seam_cr3(u32 nr_lps)
{
	return seam_stack_base_pa(nr_lps) - PAGE_SIZE;
}

static u64 seam_map_page(struct seam_mmu *mmu, u64 va, u64 pa, u64 leaf_attr)
{
	u32 level, idx;
	u64 pxe_pa = 0;
	u64 *pxe;

	pxe = (u64 *)seam_pa_to_va(mmu->root_pa);

	/* Walk non-leaf levels and fill if needed. */
	for (level = 0; level < mmu->nr_page_levels - 1; level++) {
		idx = (va >> ((mmu->nr_page_levels - 1) * 9 - level * 9 + 12)) & 0x1ff;

		if (pxe[idx] == 0) {
			pxe[idx] = mmu->next_pa | SEAM_PXE_ATTR;
			mmu->next_pa -= PAGE_SIZE;
		}

		pxe_pa = pxe[idx] & GENMASK_ULL(52, PAGE_SHIFT);
		pxe = (u64 *)seam_pa_to_va(pxe_pa);
	}

	// map leaf level
	idx = (va >> 12) & 0x1ff;
	pxe[idx] = pa | leaf_attr;

	/* Return page table PA used for mapping. */
	return pxe_pa;
}

static void seam_map_code(struct seam_mmu *mmu, u64 code_size)
{
	u64 pa = seam_code_base_pa();
	u64 va = SEAM_CODE_BASE;
	u64 i;

	for (i = 0; i < code_size; i += PAGE_SIZE) {
		seam_map_page(mmu, va, pa, SEAM_CODE_ATTR);
		va += PAGE_SIZE;
		pa += PAGE_SIZE;
	}
}

static void seam_map_stacks(struct seam_mmu *mmu, u32 nr_lps)
{
	u64 pa = seam_stack_base_pa(nr_lps);
	u64 va = SEAM_STACK_BASE;
	u32 lp;
	u64 i;

	for (lp = 0; lp < nr_lps; lp++) {
		/* Actual stack pages. */
		for (i = 0; i < SEAM_PER_LP_STACK_SIZE; i += PAGE_SIZE) {
			seam_map_page(mmu, va, pa, SEAM_STACK_ATTR);
			va += PAGE_SIZE;
			pa += PAGE_SIZE;
		}
		/* Shadow stack pages. */
		for (i = 0; i < SEAM_PER_LP_SHADOW_STACK_SIZE; i += PAGE_SIZE) {
			seam_map_page(mmu, va, pa, SEAM_SHADOW_STACK_ATTR);
			va += PAGE_SIZE;
			pa += PAGE_SIZE;
		}
	}
}

static void seam_map_keyholes(struct seam_mmu *mmu, u32 nr_lps)
{
	u64 edit_va = SEAM_KEYHOLE_EDIT_BASE;
	u64 prev_pt_pa = -1ull;
	u64 cur_pt_pa;
	u64 i;

	for (i = 0; i < SEAM_PER_LP_KEYHOLE_SIZE * nr_lps; i += PAGE_SIZE) {
		cur_pt_pa = seam_map_page(mmu, SEAM_KEYHOLE_BASE + i, 0, 0);

		/* Insert an edit mapping if a new page table was created. */
		if (cur_pt_pa != prev_pt_pa) {
			seam_map_page(mmu, edit_va, cur_pt_pa, SEAM_KEYHOLE_EDIT_ATTR);
			prev_pt_pa = cur_pt_pa;
			edit_va += PAGE_SIZE;
		}
	}
}

static u64 seam_map_data(struct seam_mmu *mmu, u32 nr_lps)
{
	u64 pa = seam_data_base_pa(nr_lps);
	u64 va = SEAM_DATA_BASE;
	u64 data_size = 0;

	/* Leave enough space for a page table for each level. */
	while (pa < mmu->next_pa - (mmu->nr_page_levels * PAGE_SIZE)) {
		seam_map_page(mmu, va, pa + data_size, SEAM_DATA_ATTR);
		va += PAGE_SIZE;
		pa += PAGE_SIZE;
		data_size += PAGE_SIZE;
	}

	return data_size;
}

static u64 seam_init_page_tables(u64 code_size)
{
	u32 nr_lps = num_possible_cpus();
	struct seam_mmu mmu;

	mmu.root_pa = seam_cr3(nr_lps);
	mmu.next_pa = mmu.root_pa - PAGE_SIZE;

	mmu.nr_page_levels = cpu_feature_enabled(X86_FEATURE_LA57) ? 5 : 4;

	seam_map_code(&mmu, code_size);

	seam_map_stacks(&mmu, nr_lps);

	seam_map_keyholes(&mmu, nr_lps);

	seam_map_page(&mmu, SEAM_SYS_INFO_BASE, seam_sys_info_pa(), SEAM_SYSINFO_ATTR);

	return seam_map_data(&mmu, nr_lps);
}

static void seam_init_sys_info(u64 data_size)
{
	struct seam_sysinfo *sysinfo = seam_va;
	u32 nr_lps = num_possible_cpus();
	u64 max_pa = get_max_mapped();

	sysinfo->socket_fms[0] = cpuid_eax(1);

	/* CMRs below 4g. */
	sysinfo->cmr[0].base = 0;
	sysinfo->cmr[0].size = min(max_pa, (3ULL * GiB));

	/* CMRs above 4g. */
	if (max_pa > (4ULL * GiB)) {
		sysinfo->cmr[1].base = (4ULL * GiB);
		sysinfo->cmr[1].size = max_pa - (4ULL * GiB);
	}

	sysinfo->version = 0;
	sysinfo->nr_lps = nr_lps;
	sysinfo->nr_sockets = 1;

	sysinfo->code.base = SEAM_CODE_BASE;
	sysinfo->code.size = SEAM_CODE_SIZE;

	sysinfo->data.base = SEAM_DATA_BASE;
	sysinfo->data.size = data_size;

	sysinfo->stack.base = SEAM_STACK_BASE;
	sysinfo->stack.size = nr_lps * (SEAM_PER_LP_STACK_SIZE + SEAM_PER_LP_SHADOW_STACK_SIZE);

	sysinfo->keyhole.base = SEAM_KEYHOLE_BASE;
	sysinfo->keyhole.size = nr_lps * SEAM_PER_LP_KEYHOLE_SIZE;

	/* Not entirely sure what gorilla math is going on here. */
	sysinfo->keyhole_edit.base = SEAM_KEYHOLE_EDIT_BASE;
	sysinfo->keyhole_edit.size = ((((sysinfo->keyhole.size / PAGE_SIZE) * 8) + 4095) * PAGE_SIZE) / PAGE_SIZE;

	/* Number of stack and TLS pages are reported as -1 for some dumb reason. */
	sysinfo->num_stack_pages = (SEAM_PER_LP_STACK_SIZE / PAGE_SIZE) - 1;
	sysinfo->num_tls_pages =  (SEAM_PER_LP_TLS_SIZE / PAGE_SIZE) - 1;

	sysinfo->seam_status = 1;
}

struct seam_vmcs {
	u64	cr3;

	u64	rip;
	u64	rsp;

	u64	fs_base;
	u64	gs_base;
};

static void seam_set_percpu_state(int cpu)
{
	struct seam_vmcs *vmcs;

	vmcs = seam_pa_to_va(seam_vmcs_base_pa() + (cpu * PAGE_SIZE));

	vmcs->cr3 = seam_cr3(num_possible_cpus());

	vmcs->rip = SEAM_CODE_BASE + seam_rip_offset;
	vmcs->rsp = SEAM_STACK_BASE + SEAM_PER_LP_STACK_SIZE - 8 +
		    (cpu * (SEAM_PER_LP_STACK_SIZE + SEAM_PER_LP_SHADOW_STACK_SIZE));

	vmcs->fs_base = SEAM_SYS_INFO_BASE;
	vmcs->gs_base = SEAM_DATA_BASE + (SEAM_PER_LP_TLS_SIZE * cpu);
}

struct seam_file {
	void	*buf;
	u64	size;
};

static void *seam_read_at(struct seam_file *f, off_t offset, size_t size)
{
	if (f->size < (offset + size))
		return NULL;

	return f->buf + offset;
}

static int seam_load_elf64(struct seam_file *f, u64 *entry, u64 *total_size)
{
	struct elf64_phdr *phdr, *ph;
	struct elf64_hdr *ehdr;
	void *data;
	u64 addr;
	int i;

	*total_size = 0;
	*entry = 0;

	ehdr = seam_read_at(f, 0, sizeof(*ehdr));
	if (!ehdr)
		return -EINVAL;

	if (ehdr->e_ident[0] != ELFMAG0 || ehdr->e_ident[1] != ELFMAG1 ||
	    ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3)
		return -EINVAL;

	if (ehdr->e_type != ET_DYN)
		return -EINVAL;

	if (ehdr->e_machine != EM_X86_64)
		return -EINVAL;

	*entry = ehdr->e_entry;

	phdr = seam_read_at(f, ehdr->e_phoff, ehdr->e_phnum * sizeof(*phdr));
	if (!phdr)
		return -EINVAL;

	for(i = 0; i < ehdr->e_phnum; i++) {
		ph = &phdr[i];

		if (ph->p_type != PT_LOAD)
			continue;

		/*
		 * Some ELF files really do have segments of zero size, just
		 * ignore them.
		*/
		if (!ph->p_memsz || !ph->p_filesz)
			continue;

		/*
		 * Some SEAM modules incorrectly pull in functions from shared
		 * libraries, e.g. memcpy(), generating a PT_LOAD entry for the
		 * Global Offset Table beyond the max code size.  Ignore 'em.
		 */
		if (ph->p_paddr > SEAM_CODE_SIZE)
			continue;

		data = seam_read_at(f, ph->p_offset, ph->p_filesz);
		if (!data)
			return -EINVAL;

		/* Adjust address by seam_base. */
		addr = seam_code_base_pa() + ph->p_paddr;
		memcpy(seam_pa_to_va(addr), data, ph->p_filesz);

		*total_size += ph->p_memsz;
	}
	return 0;
}


void __init seam_map_seamrr(unsigned long (*map) (unsigned long start,
						  unsigned long end,
						  unsigned long ps_mask))
{
	unsigned long seam_end;

	if (rdmsrl_safe(MSR_IA32_SEAMRR_BASE_SDV, &seam_base)) {
		pr_warn("unabled to read SEAM base from MSR 0x%x\n",
			MSR_IA32_SEAMRR_BASE_SDV);
		return;
	}

	seam_end = map(seam_base, seam_base + SEAM_SIZE, 1 << PG_LEVEL_2M);

	if (seam_end != seam_base + SEAM_SIZE) {
		pr_warn("failed to map SEAMRR 0x%llx - 0x%llx, end = 0x%lx\n",
			seam_base, seam_base + SEAM_SIZE, seam_end);
		return;
	}

	seam_va = __va(seam_base);
}

bool is_seam_module_loaded(void)
{
	struct seam_sysinfo *sysinfo = seam_va;

	if (!sysinfo || !sysinfo->nr_lps)
		return false;

	return !WARN_ON(sysinfo->nr_lps != num_possible_cpus());
}

int seam_load_module(const char *name, void *data, u64 size)
{
	u64 img_size, data_size;
	struct seam_file f;
	int ret, i;

	if (!seam_va)
		return -EIO;

	f.buf = data;
	f.size = size;

	/* Zero out the entirety of SEAM before loading the module. */
	memset(seam_va, 0, SEAM_SIZE);

	/*
	 * Load the module code, which writes guest memory directly.  This must be
	 * done before initializing page tables so that the image size is known.
	 */
	ret = seam_load_elf64(&f, &seam_rip_offset, &img_size);
	if (ret) {
		pr_warn("invalid SEAM module '%s'\n", name);
		return ret;
	}

	data_size = seam_init_page_tables(img_size);
	seam_init_sys_info(data_size);

	for (i = 0; i < num_possible_cpus(); i++)
		seam_set_percpu_state(i);

	pr_warn("SEAM module loaded @ %llx - %llx, entry @ %llx, cpus = %d\n",
		seam_code_base_pa(), seam_code_base_pa() + img_size - 1,
		seam_code_base_pa() + seam_rip_offset, num_possible_cpus());

	return 0;
}

int seam_load_module_from_path(const char *seam_module)
{
	loff_t size;
	void *data;
	int ret;

	ret = kernel_read_file_from_path(seam_module, &data, &size, 0,
					 READING_MODULE);
	if (ret) {
		pr_warn("unable to read SEAM module '%s'\n", seam_module);
		return ret;
	}

	ret = seam_load_module(seam_module, data, size);

	vfree(data);
	return ret;
}
EXPORT_SYMBOL_GPL(seam_load_module_from_path);
