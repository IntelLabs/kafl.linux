/*
 * This file is part of Redqueen.
 *
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KAFL_USER_H
#define KAFL_USER_H

#include <stdarg.h>
#include <stddef.h>
#include <stdarg.h>

#define HYPERCALL_KAFL_RAX_ID				0x01f
#define HYPERCALL_KAFL_ACQUIRE				0
#define HYPERCALL_KAFL_GET_PAYLOAD			1
#define HYPERCALL_KAFL_GET_PROGRAM			2
#define HYPERCALL_KAFL_GET_ARGV				3
#define HYPERCALL_KAFL_RELEASE				4
#define HYPERCALL_KAFL_SUBMIT_CR3			5
#define HYPERCALL_KAFL_SUBMIT_PANIC			6
#define HYPERCALL_KAFL_SUBMIT_KASAN			7
#define HYPERCALL_KAFL_PANIC				8
#define HYPERCALL_KAFL_KASAN				9
#define HYPERCALL_KAFL_LOCK					10
#define HYPERCALL_KAFL_INFO					11
#define HYPERCALL_KAFL_NEXT_PAYLOAD			12
#define HYPERCALL_KAFL_PRINTF				13
#define HYPERCALL_KAFL_PRINTK_ADDR			14
#define HYPERCALL_KAFL_PRINTK				15

/* user space only hypercalls */
#define HYPERCALL_KAFL_USER_RANGE_ADVISE	16
#define HYPERCALL_KAFL_USER_SUBMIT_MODE		17
#define HYPERCALL_KAFL_USER_FAST_ACQUIRE	18
/* 19 is already used for exit reason KVM_EXIT_KAFL_TOPA_MAIN_FULL */
#define HYPERCALL_KAFL_USER_ABORT			20
#define HYPERCALL_KAFL_RANGE_SUBMIT			29
#define HYPERCALL_KAFL_REQ_STREAM_DATA		30
#define HYPERCALL_KAFL_PANIC_EXTENDED		32

/* incremental snapshot (+ debug version) */
#define HYPERCALL_KAFL_CREATE_TMP_SNAPSHOT	33
#define HYPERCALL_KAFL_DEBUG_TMP_SNAPSHOT	34

/* get/set options and capabilities */
#define HYPERCALL_KAFL_GET_HOST_CONFIG		35
#define HYPERCALL_KAFL_SET_AGENT_CONFIG		36

/* write a file back to hypervisor */
#define HYPERCALL_KAFL_DUMP_FILE			37

/* hypertrash only hypercalls */
#define HYPERTRASH_HYPERCALL_MASK			0xAA000000

#define HYPERCALL_KAFL_NESTED_PREPARE		(0 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_CONFIG		(1 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_ACQUIRE		(2 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_RELEASE		(3 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_HPRINTF		(4 | HYPERTRASH_HYPERCALL_MASK)


#define PAYLOAD_BUFFER_SIZE			(256 << 10)	/* up to 256KB payloads */
#define HPRINTF_MAX_SIZE			0x1000		/* up to 4KB hprintf strings */

typedef union {
	struct {
		unsigned int dump_observed :1;
		unsigned int dump_stats :1;
		unsigned int dump_callers :1;
	};
	uint32_t raw_data;
} __attribute__((packed)) agent_flags_t;

#define MAX_PAYLOAD_LEN (PAYLOAD_BUFFER_SIZE-sizeof(int32_t)-sizeof(agent_flags_t))
typedef struct {
	agent_flags_t flags;
	int32_t size;
	uint8_t data[MAX_PAYLOAD_LEN];
} __attribute__((packed)) kAFL_payload;

typedef struct {
	uint64_t ip[4];
	uint64_t size[4];
	uint8_t enabled[4];
} kAFL_ranges;

#define KAFL_MODE_64	0
#define KAFL_MODE_32	1
#define KAFL_MODE_16	2

/* Todo: Add support for hypercall return values */
#if defined(__i386__)
static inline uint32_t kAFL_hypercall(uint32_t p1, uint32_t p2)
{
	uint32_t nr = HYPERCALL_KAFL_RAX_ID;
	asm volatile ("vmcall"
			: "=a" (nr)
			: "a"(nr), "b"(p1), "c"(p2));
	return nr;
}
#elif defined(__x86_64__)
static inline uint64_t kAFL_hypercall(uint64_t p1, uint64_t p2)
{
	uint64_t nr = HYPERCALL_KAFL_RAX_ID;
	asm volatile ("vmcall"
			: "=a" (nr)
			: "a"(nr), "b"(p1), "c"(p2));
	return nr;
}
#endif

static void hprintf(const char * format, ...)  __attribute__ ((unused));
static void hprintf(const char * format, ...)
{
	static char hprintf_buffer[HPRINTF_MAX_SIZE] __attribute__((aligned(4096)));

	va_list args;
	va_start(args, format);
	vsnprintf((char*)hprintf_buffer, HPRINTF_MAX_SIZE, format, args);
	kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)hprintf_buffer);
	//vprintf(format, args);
	va_end(args);
}

typedef struct host_config_s {
	uint32_t bitmap_size;
	uint32_t ijon_bitmap_size;
	uint32_t payload_buffer_size;
	uint32_t worker_id;
	/* more to come */
} __attribute__((packed)) host_config_t;

typedef struct agent_config_s {
	uint8_t agent_timeout_detection;
	uint8_t agent_tracing;
	uint8_t agent_ijon_tracing;
	uint8_t agent_non_reload_mode;
	uint64_t trace_buffer_vaddr;
	uint64_t ijon_trace_buffer_vaddr;

	uint8_t dump_payloads; /* is set by the hypervisor */
	/* more to come */
} __attribute__((packed)) agent_config_t;

typedef struct kafl_dump_file_s {
	uint64_t file_name_str_ptr;
	uint64_t data_ptr;
	uint64_t bytes;
	uint8_t append;
} __attribute__((packed)) kafl_dump_file_t;

#define cpuid(in,a,b,c,d)\
	asm("cpuid": "=a" (a), "=b" (b), "=c" (c), "=d" (d) : "a" (in));

static int is_nyx_vcpu(void) __attribute__((unused));
static int is_nyx_vcpu(void)
{
	unsigned long eax,ebx,ecx,edx;
	char str[8];
	int j;
	cpuid(0x80000004,eax,ebx,ecx,edx);	

	for (j=0;j<4;j++) {
		str[j] = eax >> (8*j);
		str[j+4] = ebx >> (8*j);
	}

	return !memcmp(&str, "NYX vCPU", 8);
}

#endif
