/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_OPS_H
#define __KVM_X86_TDX_OPS_H

#include <linux/compiler.h>

#include <asm/asm.h>
#include <asm/kvm_host.h>

/*
 * SEAMCALL API function leaf
 */
#define SEAMCALL_TDENTER		0
#define SEAMCALL_TDADDCX		1
#define SEAMCALL_TDADDPAGE		2
#define SEAMCALL_TDADDSEPT		3
#define SEAMCALL_TDADDVPX		4
#define SEAMCALL_TDASSIGNHKID		5
#define SEAMCALL_TDAUGPAGE		6
#define SEAMCALL_TDBLOCK		7
#define SEAMCALL_TDCONFIGKEY		8
#define SEAMCALL_TDCREATE		9
#define SEAMCALL_TDCREATEVP		10
#define SEAMCALL_TDDBGRD		11
#define SEAMCALL_TDDBGRDMEM		12
#define SEAMCALL_TDDBGWR		13
#define SEAMCALL_TDDBGWRMEM		14
#define SEAMCALL_TDDEMOTEPAGE		15
#define SEAMCALL_TDEXTENDMR		16
#define SEAMCALL_TDFINALIZEMR		17
#define SEAMCALL_TDFLUSHVP		18
#define SEAMCALL_TDFLUSHVPDONE		19
#define SEAMCALL_TDFREEHKIDS		20
#define SEAMCALL_TDINIT			21
#define SEAMCALL_TDINITVP		22
#define SEAMCALL_TDPROMOTEPAGE		23
#define SEAMCALL_TDRDPAGEMD		24
#define SEAMCALL_TDRDSEPT		25
#define SEAMCALL_TDRDVPS		26
#define SEAMCALL_TDRECLAIMHKIDS		27
#define SEAMCALL_TDRECLAIMPAGE		28
#define SEAMCALL_TDREMOVEPAGE		29
#define SEAMCALL_TDREMOVESEPT		30
#define SEAMCALL_TDSYSCONFIGKEY		31
#define SEAMCALL_TDSYSINFO		32
#define SEAMCALL_TDSYSINIT		33

#define SEAMCALL_TDSYSINITLP		35
#define SEAMCALL_TDSYSINITTDMR		36
#define SEAMCALL_TDTEARDOWN		37
#define SEAMCALL_TDTRACK		38
#define SEAMCALL_TDUNBLOCK		39
#define SEAMCALL_TDWBCACHE		40
#define SEAMCALL_TDWBINVDPAGE		41
#define SEAMCALL_TDWRSEPT		42
#define SEAMCALL_TDWRVPS		43
#define SEAMCALL_TDSYSSHUTDOWNLP	44
#define SEAMCALL_TDSYSCONFIG		45

struct tdx_ex_ret {
	union {
		/* Used to retrieve values from hardware. */
		struct {
			u64 rcx;
			u64 rdx;
			u64 r8;
			u64 r9;
			u64 r10;
		};
		/* Functions that return SEPT and level that failed. */
		struct {
			u64 septep;
			int level;
		};
		/* TDDBG{RD,WR} return the TDR, field code, and value. */
		struct {
			u64 tdr;
			u64 field;
			u64 field_val;
		};
		/* TDDBG{RD,WR}MEM return the address and its value. */
		struct {
			u64 addr;
			u64 val;
		};
		/* TDRDPAGEMD and TDRECLAIMPAGE return page metadata. */
		struct {
			u64 page_type;
			u64 owner;
			u64 page_size;
		};
		/* TDRDSEPT returns the contents of the SEPT entry. */
		struct {
			u64 septe;
			u64 ign;
		};
		/*
		 * TDSYSINFO returns the buffer address and its size, and the
		 * CMR_INFO address and its number of entries.
		 */
		struct {
			u64 buffer;
			u64 nr_bytes;
			u64 cmr_info;
			u64 nr_cmr_entries;
		};
		/*
		 * TDINIT and TDSYSINIT return CPUID info on error.  Note, only
		 * the leaf and subleaf are valid on TDINIT error.
		 */
		struct {
			u32 leaf;
			u32 subleaf;
			u32 eax_mask;
			u32 ebx_mask;
			u32 ecx_mask;
			u32 edx_mask;
			u32 eax_val;
			u32 ebx_val;
			u32 ecx_val;
			u32 edx_val;
		};
		/* TDSYSINITTDMR returns the input PA and next PA. */
		struct {
			u64 prev;
			u64 next;
		};
	};
};

#define pr_seamcall_error(op, err)				\
	pr_err("SEAMCALL[" #op "] failed: 0x%lx (cpu %d)\n",	\
	       SEAMCALL_##op ? (err) : (err), smp_processor_id());

#define tdenter(args...)		({ 0; })

#ifndef	__seamcall

#define seamcall ".byte 0x66,0x0f,0x01,0xcf"

#define __seamcall							\
	"1:" seamcall "\n\t"						\
	"jmp 3f\n\t"							\
	"2: call kvm_spurious_fault\n\t"				\
	"3:\n\t"							\
	_ASM_EXTABLE(1b, 2b)

#endif

#define seamcall_N(fn, inputs...)					\
do {									\
	long ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret)			\
		     : "a"(fn), inputs					\
		     : );						\
	return ret;							\
} while (0)

#define seamcall_0(fn)	 						\
	seamcall_N(fn, "i"(0))
#define seamcall_1(fn, rcx)	 					\
	seamcall_N(fn, "c"(rcx))
#define seamcall_2(fn, rcx, rdx)					\
	seamcall_N(fn, "c"(rcx), "d"(rdx))
#define seamcall_3(fn, rcx, rdx, __r8)					\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N(fn, "c"(rcx), "d"(rdx), "r"(r8));			\
} while (0)
#define seamcall_4(fn, rcx, rdx, __r8, __r9)				\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N(fn, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));		\
} while (0)

#define seamcall_N_2(fn, ex, inputs...)					\
do {									\
	long ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret),			\
		       "=c"((ex)->rcx), "=d"((ex)->rdx)			\
		     : "a"(fn), inputs					\
		     : );						\
	return ret;							\
} while (0)

#define seamcall_0_2(fn, ex)						\
	seamcall_N_2(fn, ex, "i"(0))
#define seamcall_1_2(fn, rcx, ex)					\
	seamcall_N_2(fn, ex, "c"(rcx))
#define seamcall_2_2(fn, rcx, rdx, ex)					\
	seamcall_N_2(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_2(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_2(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_2(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_2(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)

#define seamcall_N_3(fn, ex, inputs...)					\
do {									\
	register long r8_out asm("r8");					\
	long ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret),			\
		       "=c"((ex)->rcx), "=d"((ex)->rdx), "=r"(r8_out)	\
		     : "a"(fn), inputs					\
		     : );						\
	(ex)->r8 = r8_out;						\
	return ret;							\
} while (0)

#define seamcall_0_3(fn, ex)						\
	seamcall_N_3(fn, ex, "i"(0))
#define seamcall_1_3(fn, rcx, ex)					\
	seamcall_N_3(fn, ex, "c"(rcx))
#define seamcall_2_3(fn, rcx, rdx, ex)					\
	seamcall_N_3(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_3(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_3(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_3(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_3(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)

#define seamcall_N_4(fn, ex, inputs...)					\
do {									\
	register long r8_out asm("r8");					\
	register long r9_out asm("r9");					\
	long ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret), "=c"((ex)->rcx),	\
		       "=d"((ex)->rdx), "=r"(r8_out), "=r"(r9_out)	\
		     : "a"(fn), inputs					\
		     : );						\
	(ex)->r8 = r8_out;						\
	(ex)->r9 = r9_out;						\
	return ret;							\
} while (0)

#define seamcall_0_4(fn, ex)						\
	seamcall_N_4(fn, ex, "i"(0))
#define seamcall_1_4(fn, rcx, ex)					\
	seamcall_N_4(fn, ex, "c"(rcx))
#define seamcall_2_4(fn, rcx, rdx, ex)					\
	seamcall_N_4(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_4(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_4(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_4(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_4(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)

#define seamcall_N_5(fn, ex, inputs...)					\
do {									\
	register long r8_out asm("r8");					\
	register long r9_out asm("r9");					\
	register long r10_out asm("r10");				\
	long ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret), "=c"((ex)->rcx),	\
		       "=d"((ex)->rdx), "=r"(r8_out), "=r"(r9_out),	\
		       "=r"(r10_out)					\
		     : "a"(fn), inputs					\
		     : );						\
	(ex)->r8 = r8_out;						\
	(ex)->r9 = r9_out;						\
	(ex)->r10 = r10_out;						\
	return ret;							\
} while (0)

#define seamcall_0_5(fn, ex)						\
	seamcall_N_5(fn, ex, "i"(0))
#define seamcall_1_5(fn, rcx, ex)					\
	seamcall_N_5(fn, ex, "c"(rcx))
#define seamcall_2_5(fn, rcx, rdx, ex)					\
	seamcall_N_5(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_5(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_5(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_5(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_5(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)

static inline long tdaddcx(hpa_t tdr, hpa_t addr)
{
	seamcall_2(SEAMCALL_TDADDCX, addr, tdr);
}

static inline long tdaddpage(hpa_t tdr, gpa_t gpa, hpa_t hpa, hpa_t source,
			     struct tdx_ex_ret *ex)
{
	seamcall_4_2(SEAMCALL_TDADDPAGE, gpa, tdr, hpa, source, ex);
}

static inline long tdaddsept(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
			     struct tdx_ex_ret *ex)
{
	seamcall_3_2(SEAMCALL_TDADDSEPT, gpa | level, tdr, page, ex);
}

static inline long tdaddvpx(hpa_t tdvpr, hpa_t addr)
{
	seamcall_2(SEAMCALL_TDADDVPX, addr, tdvpr);
}

static inline long tdassignhkid(hpa_t tdr, int hkid)
{
	seamcall_3(SEAMCALL_TDASSIGNHKID, tdr, 0, hkid);
}

static inline long tdaugpage(hpa_t tdr, gpa_t gpa, hpa_t hpa,
			     struct tdx_ex_ret *ex)
{
	seamcall_3_2(SEAMCALL_TDAUGPAGE, gpa, tdr, hpa, ex);
}

static inline long tdblock(hpa_t tdr, gpa_t gpa, int level,
			   struct tdx_ex_ret *ex)
{
	seamcall_2_2(SEAMCALL_TDBLOCK, gpa | level, tdr, ex);
}

static inline long tdconfigkey(hpa_t tdr)
{
	seamcall_1(SEAMCALL_TDCONFIGKEY, tdr);
}

static inline long tdcreate(hpa_t tdr, int hkid)
{
	seamcall_2(SEAMCALL_TDCREATE, tdr, hkid);
}

static inline long tdcreatevp(hpa_t tdr, hpa_t tdvpr)
{
	seamcall_2(SEAMCALL_TDCREATEVP, tdvpr, tdr);
}

static inline long tddbgrd(hpa_t tdr, u64 field, struct tdx_ex_ret *ex)
{
	seamcall_2_3(SEAMCALL_TDDBGRD, tdr, field, ex);
}

static inline long tddbgwr(hpa_t tdr, u64 field, u64 val, u64 mask,
			   struct tdx_ex_ret *ex)
{
	seamcall_4_3(SEAMCALL_TDDBGWR, tdr, field, val, mask, ex);
}

static inline long tddbgrdmem(hpa_t addr, struct tdx_ex_ret *ex)
{
	seamcall_1_2(SEAMCALL_TDDBGRDMEM, addr, ex);
}

static inline long tddbgwrmem(hpa_t addr, u64 val, struct tdx_ex_ret *ex)
{
	seamcall_2_2(SEAMCALL_TDDBGWRMEM, addr, val, ex);
}

static inline long tddemotepage(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
				struct tdx_ex_ret *ex)
{
	seamcall_3_2(SEAMCALL_TDDEMOTEPAGE, gpa | level, tdr, page, ex);
}

static inline long tdextendmr(hpa_t tdr, gpa_t gpa, struct tdx_ex_ret *ex)
{
	seamcall_2_2(SEAMCALL_TDEXTENDMR, gpa, tdr, ex);
}

static inline long tdfinalizemr(hpa_t tdr)
{
	seamcall_1(SEAMCALL_TDFINALIZEMR, tdr);
}

static inline long tdflushvp(hpa_t tdvpr)
{
	seamcall_1(SEAMCALL_TDFLUSHVP, tdvpr);
}

static inline long tdflushvpdone(hpa_t tdvpr)
{
	seamcall_1(SEAMCALL_TDFLUSHVPDONE, tdvpr);
}

static inline long tdfreehkids(hpa_t tdr)
{
	seamcall_1(SEAMCALL_TDFREEHKIDS, tdr);
}

static inline long tdinit(hpa_t tdr, hpa_t td_params, struct tdx_ex_ret *ex)
{
	seamcall_2_2(SEAMCALL_TDINIT, tdr, td_params, ex);
}

static inline long tdinitvp(hpa_t tdvpr, u64 rcx)
{
	seamcall_2(SEAMCALL_TDINITVP, tdvpr, rcx);
}

static inline long tdpromotepage(hpa_t tdr, gpa_t gpa, int level,
				 struct tdx_ex_ret *ex)
{
	seamcall_2_2(SEAMCALL_TDPROMOTEPAGE, gpa | level, tdr, ex);
}

static inline long tdrdpagemd(hpa_t page, struct tdx_ex_ret *ex)
{
	seamcall_1_3(SEAMCALL_TDRDPAGEMD, page, ex);
}

static inline long tdrdsept(hpa_t tdr, gpa_t gpa, int level,
			    struct tdx_ex_ret *ex)
{
	seamcall_2_2(SEAMCALL_TDRDSEPT, gpa | level, tdr, ex);
}

static inline long tdrdvps(hpa_t tdvpr, u64 field, struct tdx_ex_ret *ex)
{
	seamcall_2_3(SEAMCALL_TDRDVPS, tdvpr, field, ex);
}

static inline long tdreclaimhkids(hpa_t tdr)
{
	seamcall_1(SEAMCALL_TDRECLAIMHKIDS, tdr);
}

static inline long tdreclaimpage(hpa_t page, struct tdx_ex_ret *ex)
{
	seamcall_1_3(SEAMCALL_TDRECLAIMPAGE, page, ex);
}

static inline long tdremovepage(hpa_t tdr, gpa_t gpa, int level,
				struct tdx_ex_ret *ex)
{
	seamcall_2_2(SEAMCALL_TDREMOVEPAGE, gpa | level, tdr, ex);
}

static inline long tdremovesept(hpa_t tdr, gpa_t gpa, int level,
				struct tdx_ex_ret *ex)
{
	seamcall_2_2(SEAMCALL_TDREMOVESEPT, gpa | level, tdr, ex);
}

static inline long tdsysconfig(hpa_t tdmr, int nr_entries, int hkid)
{
	seamcall_3(SEAMCALL_TDSYSCONFIG, tdmr, nr_entries, hkid);
}

static inline long tdsysconfigkey(void)
{
	seamcall_0(SEAMCALL_TDSYSCONFIGKEY);
}

static inline long tdsysinfo(hpa_t tdsysinfo, int nr_bytes, hpa_t cmr_info,
			     int nr_cmr_entries, struct tdx_ex_ret *ex)
{
	seamcall_4_4(SEAMCALL_TDSYSINFO, tdsysinfo, nr_bytes, cmr_info,
			    nr_cmr_entries, ex);
}

static inline long tdsysinit(u64 attributes, struct tdx_ex_ret *ex)
{
	seamcall_1_5(SEAMCALL_TDSYSINIT, attributes, ex);
}

static inline long tdsysinitlp(struct tdx_ex_ret *ex)
{
	seamcall_0_3(SEAMCALL_TDSYSINITLP, ex);
}

static inline long tdsysinittdmr(hpa_t tdmr, struct tdx_ex_ret *ex)
{
	seamcall_1_2(SEAMCALL_TDSYSINITTDMR, tdmr, ex);
}

static inline long tdsysshutdownlp(void)
{
	seamcall_0(SEAMCALL_TDSYSSHUTDOWNLP);
}

static inline long tdteardown(hpa_t tdr)
{
	seamcall_1(SEAMCALL_TDTEARDOWN, tdr);
}

static inline long tdtrack(hpa_t tdr)
{
	seamcall_1(SEAMCALL_TDTRACK, tdr);
}

static inline long tdunblock(hpa_t tdr, gpa_t gpa, int level,
			     struct tdx_ex_ret *ex)
{
	seamcall_2_2(SEAMCALL_TDUNBLOCK, gpa | level, tdr, ex);
}

static inline long tdwbcache(bool resume)
{
	seamcall_1(SEAMCALL_TDWBCACHE, resume ? 1 : 0);
}

static inline long tdwbinvdpage(hpa_t page)
{
	seamcall_1(SEAMCALL_TDWBINVDPAGE, page);
}

static inline long tdwrsept(hpa_t tdr, gpa_t gpa, int level, u64 val,
			    struct tdx_ex_ret *ex)
{
	seamcall_3_2(SEAMCALL_TDWRSEPT, gpa | level, tdr, val, ex);
}

static inline long tdwrvps(hpa_t tdvpr, u64 field, u64 val, u64 mask,
			   struct tdx_ex_ret *ex)
{
	seamcall_4_3(SEAMCALL_TDWRVPS, tdvpr, field, val, mask, ex);
}

#endif /* __KVM_X86_TDX_OPS_H */
