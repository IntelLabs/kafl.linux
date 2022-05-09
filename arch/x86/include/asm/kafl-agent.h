/*
 * Copyright 2022 Intel Corporation
 * SPDX-License-Identifier: MIT
 */

#ifndef KAFL_AGENT_H
#define KAFL_AGENT_H

#include <linux/kernel.h>
#include <linux/string.h>

#include <asm/tdx.h>

enum kafl_event {
	KAFL_ENABLE,
	KAFL_START,
	KAFL_ABORT,
	KAFL_SETCR3,
	KAFL_DONE,
	KAFL_PANIC,
	KAFL_KASAN,
	KAFL_UBSAN,
	KAFL_HALT,
	KAFL_REBOOT,
	KAFL_SAFE_HALT,
	KAFL_TIMEOUT,
	KAFL_ERROR,
	KAFL_PAUSE,
	KAFL_RESUME,
	KAFL_TRACE,
	KAFL_EVENT_MAX
};

void kafl_fuzz_event(enum kafl_event e);

void kafl_fuzz_function(char *fname);
void kafl_fuzz_function_disable(char *fname);

size_t kafl_fuzz_buffer(void* fuzz_buf, const void *orig_buf, const uintptr_t addr,
                        const size_t num_bytes, const enum tdx_fuzz_loc type);

int kafl_vprintk(const char *fmt, va_list args);
void kafl_hprintf(const char *fmt, ...) __attribute__ ((unused, format (printf, 1, 2)));

#endif /* KAFL_AGENT_H */
