/*
 * kAFL agent for fuzzing #VE returns
 *
 * Dynamically initiate handshake + snapshot upon first use
 */

#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/percpu.h>
#include <linux/debugfs.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <asm/tdx.h>
#include <asm/trace/tdx.h>
#include <asm-generic/sections.h>

#include <linux/pci.h>
#include <linux/msi.h>
#include <linux/of_device.h>
#include <linux/of_pci.h>
#include <linux/pci_hotplug.h>

#include <asm/kafl-agent.h>
#include <asm/kafl-api.h>

#undef pr_fmt
#define pr_fmt(fmt) "kAFL: " fmt


bool agent_initialized = false;
bool fuzz_enabled = false;
bool fuzz_tdcall = true;   // enable TDX fuzzing by default
bool fuzz_tderror = false; // TDX error fuzzing not supported

/* abort at end of payload - otherwise we keep feeding unmodified input
 * which means we see coverage that is not represented in the payload */
bool exit_at_eof = true;

agent_config_t agent_config = {0};
host_config_t host_config = {0};

char hprintf_buffer[HPRINTF_MAX_SIZE] __attribute__((aligned(4096)));
kafl_dump_file_t dump_file __attribute__((aligned(4096)));
uint32_t location_stats[TDX_FUZZ_MAX];

/* kmalloc() may not always be available - e.g. early boot */
//#define KAFL_ASSUME_KMALLOC
#ifdef KAFL_ASSUME_KMALLOC
size_t payload_buffer_size = 0;
size_t observed_buffer_size = 0;
uint8_t *payload_buffer = NULL;
uint8_t *observed_buffer = NULL;
#else
size_t payload_buffer_size = PAYLOAD_MAX_SIZE;
size_t observed_buffer_size = 2*PAYLOAD_MAX_SIZE;
uint8_t payload_buffer[PAYLOAD_MAX_SIZE] __attribute__((aligned(4096)));
uint8_t observed_buffer[2*PAYLOAD_MAX_SIZE] __attribute__((aligned(4096)));
#endif


static struct {
		bool dump_observed;
		bool dump_stats;
		bool dump_callers;
} agent_flags;

u8 *ve_buf;
u32 ve_num;
u32 ve_pos;
u32 ve_mis;

u8 *ob_buf;
u32 ob_num;
u32 ob_pos;

const char *kafl_event_name[KAFL_EVENT_MAX] = {
	"KAFL_ENABLE",
	"KAFL_START",
	"KAFL_ABORT",
	"KAFL_SETCR3",
	"KAFL_DONE",
	"KAFL_PAUSE",
	"KAFL_RESUME",
	"KAFL_TRACE",
	"KAFL_PANIC",
	"KAFL_KASAN",
	"KAFL_UBSAN",
	"KAFL_HALT",
	"KAFL_REBOOT",
	"KAFL_SAFE_HALT",
	"KAFL_TIMEOUT",
	"KAFL_ERROR",
};

void kafl_raise_panic(void) {
	kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
}

void kafl_raise_kasan(void) {
	kAFL_hypercall(HYPERCALL_KAFL_KASAN, 0);
}

void kafl_agent_setrange(int id, void* start, void* end)
{
	uintptr_t range[3];
	range[0] = (uintptr_t)start & PAGE_MASK;
	range[1] = ((uintptr_t)end + PAGE_SIZE-1) & PAGE_MASK;
	range[2] = id;

	kafl_hprintf("Setting range %lu: %lx-%lx\n", range[2], range[0], range[1]);
	kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uintptr_t)range);
}

void kafl_habort(char *msg)
{
	kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)msg);
}

void kafl_hprintf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vsnprintf((char*)hprintf_buffer, HPRINTF_MAX_SIZE, fmt, args);
	kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)hprintf_buffer);
	va_end(args);
}

static
void kafl_dump_observed_payload(char *filename, int append, uint8_t *buf, uint32_t buflen)
{
	static char fname_buf[128];
	strncpy(fname_buf, filename, sizeof(fname_buf));
	dump_file.file_name_str_ptr = (uint64_t)fname_buf;
	dump_file.data_ptr = (uint64_t)buf;
	dump_file.bytes = buflen;
	dump_file.append = append;

	kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)&dump_file);
}

void kafl_agent_setcr3(void)
{
	pr_debug("Submitting current CR3 value to hypervisor...\n");
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
}

void kafl_stats_clear(void)
{
	memset(location_stats, 0, sizeof(location_stats));
}

void kafl_trace_locations(void)
{
#ifdef CONFIG_TDX_FUZZ_KAFL_TRACE_LOCATIONS
	printk("kAFL locations: msrs=%u, mmio=%u, pio=%u, virtio=%u, rng=%u; cpuid=<%u,%u,%u,%u>; err=<%u,%u,%u,%u>\n",
			location_stats[TDX_FUZZ_MSR_READ],
			location_stats[TDX_FUZZ_MMIO_READ],
			location_stats[TDX_FUZZ_PORT_IN],
			location_stats[TDX_FUZZ_VIRTIO],
			location_stats[TDX_FUZZ_RANDOM],
			location_stats[TDX_FUZZ_CPUID1],
			location_stats[TDX_FUZZ_CPUID2],
			location_stats[TDX_FUZZ_CPUID3],
			location_stats[TDX_FUZZ_CPUID4],
			location_stats[TDX_FUZZ_MSR_READ_ERR],
			location_stats[TDX_FUZZ_MSR_WRITE_ERR],
			location_stats[TDX_FUZZ_MAP_ERR],
			location_stats[TDX_FUZZ_PORT_IN_ERR]);

	kafl_stats_clear();
#endif
	return;
}

void kafl_agent_init(void)
{
	kAFL_payload *payload = NULL;

	if (agent_initialized) {
		kafl_habort("Warning: Agent was already initialized!\n");
	}

	kafl_hprintf("[*] Initialize kAFL Agent\n");

	/* initial fuzzer handshake */
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	/* used for code injection and libxdc disassembly */
#if defined(__i386__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_32);
#elif defined(__x86_64__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
#endif


	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

	kafl_hprintf("[host_config] bitmap sizes = <0x%x,0x%x>\n", host_config.bitmap_size, host_config.ijon_bitmap_size);
	kafl_hprintf("[host_config] payload size = %dKB\n", host_config.payload_buffer_size/1024);
	kafl_hprintf("[host_config] worker id = %02u\n", host_config.worker_id);

#ifdef KAFL_ASSUME_KMALLOC
	payload_buffer_size = host_config.payload_buffer_size;
	observed_buffer_size = 2*host_config.payload_buffer_size;
	payload_buffer = kmalloc(payload_buffer_size, GFP_KERNEL|__GFP_NOFAIL);
	observed_buffer = kmalloc(observed_buffer_size, GFP_KERNEL|__GFP_NOFAIL);

	if (!payload_buffer || !observed_buffer) {
		kafl_habort("Failed to allocate host payload buffer!\n");
	}
#else
	if (host_config.payload_buffer_size > PAYLOAD_MAX_SIZE) {
		kafl_habort("Insufficient payload buffer size!\n");
	}
#endif

	/* ensure that the virtual memory is *really* present in physical memory... */
	memset(payload_buffer, 0xff, payload_buffer_size);
	memset(observed_buffer, 0xff, observed_buffer_size);

	kafl_hprintf("Submitting payload buffer address to hypervisor (%lx)\n", (uintptr_t)payload_buffer);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);

	agent_config.agent_magic = NYX_AGENT_MAGIC;
	agent_config.agent_version = NYX_AGENT_VERSION;
	agent_config.agent_timeout_detection = 0;
	agent_config.agent_tracing = 0;
	agent_config.agent_ijon_tracing = 0;
	agent_config.agent_non_reload_mode = 0;
	agent_config.trace_buffer_vaddr = 0;
	agent_config.ijon_trace_buffer_vaddr = 0;
	//agent_config.coverage_bitmap_size = host_config.bitmap_size;
	agent_config.input_buffer_size = 0;
	agent_config.dump_payloads = 0;
	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

	// set PT filter ranges based on exported linker map symbols in sections.h
	kafl_agent_setrange(0, _stext, _etext);
	kafl_agent_setrange(1, _sinittext, _einittext);

	// fetch fuzz input for later #VE injection
	kafl_hprintf("Starting kAFL loop...\n");
	kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

	payload = (kAFL_payload*)payload_buffer;
	ve_buf = payload->data;
	ve_num = payload->size;
	ve_pos = 0;
	ve_mis = 0;

	if (payload->flags.raw_data != 0) {
		pr_debug("Runtime payload->flags=0x%04x\n", payload->flags.raw_data);
		pr_debug("\t dump_observed = %u\n",         payload->flags.dump_observed);
		pr_debug("\t dump_stats = %u\n",            payload->flags.dump_stats);
		pr_debug("\t dump_callers = %u\n",          payload->flags.dump_callers);

		// debugfs cannot handle the bitfield..
		agent_flags.dump_observed = payload->flags.dump_observed;
		agent_flags.dump_stats    = payload->flags.dump_stats;
		agent_flags.dump_callers  = payload->flags.dump_callers;

		// dump modes are exclusive - sharing the observed_* and ob_* buffers
		BUG_ON(agent_flags.dump_observed && agent_flags.dump_callers);
		BUG_ON(agent_flags.dump_observed && agent_flags.dump_stats);
		BUG_ON(agent_flags.dump_callers  && agent_flags.dump_stats);
	}

	if (agent_flags.dump_observed) {
		ob_buf = observed_buffer;
		ob_num = sizeof(observed_buffer);
		ob_pos = 0;
	}

	kafl_stats_clear();
	agent_initialized = true;

	// start coverage tracing
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 
}

void kafl_agent_stats(void)
{
	if (!agent_initialized) {
		// agent stats are undefined!
		return;
	}

	// Dump observed values
	if (agent_flags.dump_observed) {
		pr_debug("Dumping observed input...\n");
		kafl_dump_observed_payload("payload_XXXXXX", false, (uint8_t*)ob_buf, ob_pos);
	}

	if (agent_flags.dump_stats) {

		// flag if payload buffer is >90% and we quit due to missing input
		char maxed_out = ' ';
		size_t max_plen = payload_buffer_size - sizeof(int32_t) - sizeof(agent_flags_t);
		if (ve_mis && max_plen/10*9 < (ve_pos) * sizeof(ve_buf[0])) {
			maxed_out = '*';
		}

		ob_num = snprintf(observed_buffer,
				          observed_buffer_size,
						  "%05u/%u: %5u, %5u, %5u;\trng=%u; cpuid=<%u,%u,%u,%u>; virtio=%u; err=<%u,%u,%u,%u> %c\n",
				          ve_pos, ve_mis,
				          location_stats[TDX_FUZZ_MSR_READ],
				          location_stats[TDX_FUZZ_MMIO_READ],
				          location_stats[TDX_FUZZ_PORT_IN],
				          location_stats[TDX_FUZZ_RANDOM],
				          location_stats[TDX_FUZZ_CPUID1],
				          location_stats[TDX_FUZZ_CPUID2],
				          location_stats[TDX_FUZZ_CPUID3],
				          location_stats[TDX_FUZZ_CPUID4],
				          location_stats[TDX_FUZZ_VIRTIO],
						  location_stats[TDX_FUZZ_MSR_READ_ERR],
						  location_stats[TDX_FUZZ_MSR_WRITE_ERR],
						  location_stats[TDX_FUZZ_MAP_ERR],
						  location_stats[TDX_FUZZ_PORT_IN_ERR],
						  maxed_out);
		pr_debug("Dumping fuzzer location stats\n");
		kafl_dump_observed_payload("fuzzer_location_stats.lst", true,
			   observed_buffer, ob_num);
	}

	kafl_trace_locations();
}

void kafl_agent_done(void)
{
	if (!agent_initialized) {
		kafl_habort("Attempt to finish kAFL run but never initialized\n");
	}

	kafl_agent_stats();

	// Stops tracing and restore the snapshot for next round
	// Non-zero argument triggers stream_expand mutation in kAFL
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, ve_mis*sizeof(ve_buf[0]));
}

char *tdx_fuzz_loc_str[] = {
	"MSR",
	"MIO",
	"PIO",
	"CPUID1",
	"CPUID2",
	"CPUID3",
	"CPUID4",
	"ERR_RMSR",
	"ERR_WMSR",
	"ERR_MMAP",
	"ERR_PIO",
	"VIRTIO",
	"RANDOM",
};

/*
 * Return 0 to skip fuzzing based on type/addr
 */
static bool kafl_fuzz_filter(uintptr_t addr, enum tdx_fuzz_loc type)
{
	switch(type) {
#ifdef CONFIG_TDX_FUZZ_KAFL_SKIP_MSR
		case TDX_FUZZ_MSR_READ:
			return 0;
#endif
#ifdef CONFIG_TDX_FUZZ_KAFL_SKIP_RNG_SEEDING
		case TDX_FUZZ_RANDOM:
			return 0;
#endif
		case TDX_FUZZ_PORT_IN:
			switch (addr) {
#ifdef CONFIG_TDX_FUZZ_KAFL_SKIP_ACPI_PIO
			/*
			 * Multiple relevant PIO regions, may have to activate depending on target
			 * e.g. https://qemu.readthedocs.io/en/latest/specs/acpi_pci_hotplug.html
			 */
				case 0xb000 ... 0xb006: // ACPI init?
				case 0xafe0 ... 0xafe2: // ACPI PCI hotplug
					return 0;
#endif
#ifdef CONFIG_TDX_FUZZ_KAFL_SKIP_PCI_SCAN
				case 0xcf8 ... 0xcff:
				case 0xc000 ... 0xcfff:
					return 0;
#endif
				default:
					return 1;
			}
		case TDX_FUZZ_MMIO_READ:
			switch (addr) {
#ifdef CONFIG_TDX_FUZZ_KAFL_SKIP_IOAPIC_READS
				case 0xfec00000 ... 0xfec00010: // IOAPIC?
					return 0;
#endif
				default:
					return 1;
			}
#ifndef CONFIG_TDX_FUZZ_KAFL_VIRTIO
		case TDX_FUZZ_VIRTIO:
			return 0;
#endif
#ifdef CONFIG_TDX_FUZZ_KAFL_SKIP_CPUID
		case TDX_FUZZ_CPUID1:
		case TDX_FUZZ_CPUID2:
		case TDX_FUZZ_CPUID3:
		case TDX_FUZZ_CPUID4:
			return 0;
#endif
		case TDX_FUZZ_DEBUGFS:
		default:
			; // continue to fuzzing
	}

	return 1;
}

static size_t _kafl_fuzz_buffer(void *buf, size_t num_bytes)
{
	if (ve_pos + num_bytes <= ve_num) {
		memcpy(buf, ve_buf + ve_pos, num_bytes);
		ve_pos += num_bytes;
		return num_bytes;
	}

	// insufficient fuzz buffer!
	ve_mis += num_bytes;
	if (exit_at_eof && !agent_flags.dump_observed) {
		kafl_agent_done(); /* no return */
	}
	return 0;
}

/*
 * Fuzz target buffer `fuzz_buf` depending on input and add/type filter settings
 * Returns number of bytes actually fuzzed (typically all or nothing)
 */
size_t kafl_fuzz_buffer(void* fuzz_buf, const void *orig_buf,
                     const uintptr_t addr, const size_t num_bytes,
                     const enum tdx_fuzz_loc type)
{
	size_t num_fuzzed = 0;

	if (!kafl_fuzz_filter(addr, type)) {
		return 0;
	}

	/*
	 * Do trace event + location statis only for things we actually would have
	 * fuzzed. Actual fuzzing is still gated by fuzz_enable setting.
	 */
	location_stats[type]++;
	trace_tdx_fuzz((u64)__builtin_return_address(0), num_bytes, 0, 0, type);

	if (!fuzz_enabled) {
		return 0;
	}

	/*
	 * If agent was set to 'enable' only, perform init + snapshot
	 * here at last possible moment before first injection
	 *
	 * Note: If the harness/config does not actually consume any
	 * input, the fuzzer frontend will wait forever on this..
	 */
	if (!agent_initialized) {
		kafl_agent_init();
	}

	if (agent_flags.dump_callers) {
		pr_warn("\nfuzz_var: %s[%ld], addr: %16lx, isr: %lx\n",
				tdx_fuzz_loc_str[type], num_bytes, addr, in_interrupt());
		if (type == TDX_FUZZ_PORT_IN && !tdx_allowed_port(addr)) {
			pr_warn("\tWarning: port %lx is outside allow-list!\n", addr);
		}
		dump_stack();
	}

	num_fuzzed = _kafl_fuzz_buffer(fuzz_buf, num_bytes);

	if (agent_flags.dump_observed) {
		// record input seen/used on this execution
		// with exit_at_eof=0, this should produce good seeds?
		if (ob_pos + num_bytes > ob_num) {
			pr_warn("Warning: insufficient space in dump_payload\n");
			kafl_agent_done();
		}

		memcpy(ob_buf + ob_pos, fuzz_buf, num_fuzzed);
		ob_pos += num_fuzzed;
		memcpy(ob_buf + ob_pos, orig_buf, num_bytes-num_fuzzed);
		ob_pos += (num_bytes-num_fuzzed);
	}

	return num_fuzzed;
}

u64 tdx_fuzz(u64 orig_var, uintptr_t addr, int size, enum tdx_fuzz_loc type)
{
	u64 fuzzed_var;

	if (fuzz_tdcall) {
		if (size == kafl_fuzz_buffer(&fuzzed_var, &orig_var, addr, size, type)) {
			return fuzzed_var;
		}
	}
	return orig_var;
}

bool tdx_fuzz_err(enum tdx_fuzz_loc type)
{
	// for filtering stimulus payloads, raise a trace event in any case
	location_stats[type]++;
	trace_tdx_fuzz((u64)__builtin_return_address(0), 1, 0, 1, type);

	if (!fuzz_enabled || !fuzz_tderror) {
		return false;
	}
	
	WARN(1,"tdx_fuzz_err() is not implemented\n");
	return false;
}

struct disallowlist_entry {
        struct list_head next;
        char *buf;
};
static __initdata_or_module LIST_HEAD(disallowed_fuzzing_calls);

static int __init fuzzing_disallow(char *str)
{
        char *str_entry;
        struct disallowlist_entry *entry;

        /* str argument is a comma-separated list of functions */
        do {
                str_entry = strsep(&str, ",");
                if (str_entry) {
                        pr_debug("disabling fuzzing for call %s\n", str_entry);
                        entry = memblock_alloc(sizeof(*entry),
                                               SMP_CACHE_BYTES);
                        if (!entry)
                                panic("%s: Failed to allocate %zu bytes\n",
                                      __func__, sizeof(*entry));
                        entry->buf = memblock_alloc(strlen(str_entry) + 1,
                                                    SMP_CACHE_BYTES);
                        if (!entry->buf)
                                panic("%s: Failed to allocate %zu bytes\n",
                                      __func__, strlen(str_entry) + 1);
                        strcpy(entry->buf, str_entry);
                        list_add(&entry->next, &disallowed_fuzzing_calls);
                }
        } while (str_entry);

        return 0;
}

__setup("fuzzing_disallow=", fuzzing_disallow);

static bool has_been_initialized = false;
static bool has_been_enabled = false;

static int kp_handler_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kprobe *p = &ri->rph->rp->kp;
	pr_info("pause fuzzing for '%s' fuzz_enabled=%d, agent_initialized=%d\n", p->symbol_name, fuzz_enabled, agent_initialized);
	has_been_initialized = agent_initialized;
	has_been_enabled = fuzz_enabled;
	kafl_fuzz_event(KAFL_PAUSE);
	return 0;
}

static int kp_handler_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kprobe *p = &ri->rph->rp->kp;
	// Reset fuzzing enable status
	pr_info("reset fuzzing state for '%s' fuzz_enabled=%d, has_been_enabled=%d, agent_initialized=%d\n", p->symbol_name, fuzz_enabled, has_been_enabled, agent_initialized);
	fuzz_enabled = has_been_enabled;

	return 0;
}

static int kp_harness_handler_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kprobe *p = &ri->rph->rp->kp;

	pr_info("start fuzzing for %s\n", p->symbol_name);
	kafl_fuzz_event(KAFL_TRACE);
	//kafl_fuzz_event(KAFL_START);
	//dump_stack();
	kafl_fuzz_event(KAFL_ENABLE);
	return 0;
}

static int kp_harness_handler_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kprobe *p = &ri->rph->rp->kp;

	kafl_fuzz_event(KAFL_TRACE);
	kafl_fuzz_event(KAFL_DONE);
	pr_info("end fuzzing for %s (SHOULD NOT REACH THIS!!)\n", p->symbol_name);
	return 0;
}

/*
 * Sets up intialization if single function harness.
 * Set boot param fuzzing_func_harness=funcname, to enable
 * kprobe-based single function harness for `funcname`.
 */
static char __initdata_or_module fuzzing_func_target[256] = {0};
static int __init fuzzing_func_harness(char *str)
{
	strncpy(fuzzing_func_target, str, 255);
	return 0;
}
__setup("fuzzing_func_harness=", fuzzing_func_harness);


static int __init tdx_fuzz_func_harness_init(void)
{
	if (strlen(fuzzing_func_target) > 0) {
		kafl_fuzz_function(fuzzing_func_target);
	}
	return 0;

}
// kprobe setup seems to work at core initcalls
core_initcall(tdx_fuzz_func_harness_init)

#define TDX_MAX_NUM_KPROBES 16
static struct kretprobe tdx_kprobes[TDX_MAX_NUM_KPROBES] = {0};
static int tdx_kprobes_n = 0;

static int __init tdx_fuzz_filter_init(void)
{
	int ret;

	struct disallowlist_entry *entry;
	struct kretprobe *kp;
	static bool initialized = false;

	if (initialized)
		return 0;
	initialized = true;

	list_for_each_entry(entry, &disallowed_fuzzing_calls, next) {
		pr_info("disable fuzzing mutation for %s\n", entry->buf);
		//struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
		if (tdx_kprobes_n >= TDX_MAX_NUM_KPROBES) {
			pr_info("%s: max number of probes reached (%d)\n", __func__, tdx_kprobes_n);
			return 1;
		}
		kp = &tdx_kprobes[tdx_kprobes_n++];
		kp->kp.symbol_name = entry->buf;
		kp->entry_handler = kp_handler_pre;
		kp->handler = kp_handler_post;
		kp->maxactive = 20;
		ret = register_kretprobe(kp);
		if (ret < 0) {
			pr_info("register_kprobe failed, returned %d\n", ret);
			continue;
		}
		ret = enable_kretprobe(kp);
		if (ret < 0) {
			pr_info("enable_kprobe failed, returned %d\n", ret);
			continue;
		}
		pr_info("Planted kprobe at %lx\n", (uintptr_t)kp->kp.addr);
	}

	return ret;

}

core_initcall(tdx_fuzz_filter_init);

void kafl_fuzz_function(char *fname)
{
	int ret;
	struct kretprobe *kp;
	char *fname_cpy;

	pr_info("enable fuzzing harness for %s\n", fname);
	kp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL);
	if (!kp) {
		pr_info("%s cannot allocate memory with kzalloc\n", __func__);
		return;
	}

	fname_cpy = kzalloc(strlen(fname) + 1, GFP_KERNEL);
	if (!fname_cpy) {
		pr_info("%s cannot allocate memory with kzalloc\n", __func__);
		return;
	}
	strncpy(fname_cpy, fname, strlen(fname) + 1);

	kp->kp.symbol_name = fname_cpy;
	kp->entry_handler = kp_harness_handler_pre;
	kp->handler = kp_harness_handler_post;
	ret = register_kretprobe(kp);
	if (ret < 0) {
		pr_info("register_kretprobe failed, returned %d\n", ret);
	}
	ret = enable_kretprobe(kp);
	if (ret < 0) {
		pr_info("enable_kretprobe failed, returned %d\n", ret);
	}
	pr_info("Planted kretprobe at %lx\n", (uintptr_t)kp->kp.addr);

}


void kafl_fuzz_function_disable(char *fname)
{
	int ret;
	struct kretprobe *kp;
	char *fname_cpy;

	pr_info("disable fuzzing for %s\n", fname);
	kp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL);

	fname_cpy = kzalloc(strlen(fname) + 1, GFP_KERNEL);
	strncpy(fname_cpy, fname, strlen(fname) + 1);

	kp->kp.symbol_name = fname_cpy;
	kp->entry_handler = kp_handler_pre;
	kp->handler = kp_handler_post;
	kp->maxactive = 20;
	ret = register_kretprobe(kp);
	if (ret < 0) {
		pr_info("register_kretprobe failed, returned %d\n", ret);
	}
	ret = enable_kretprobe(kp);
	if (ret < 0) {
		pr_info("enable_kretprobe failed, returned %d\n", ret);
	}
	pr_info("Planted kretprobe at %lx\n", (uintptr_t)kp->kp.addr);

}


void kafl_fuzz_event(enum kafl_event e)
{
	// pre-init actions
	switch (e) {
		case KAFL_START:
			pr_warn("[*] Agent start!\n");
			kafl_agent_init();
			fuzz_enabled = true;
			return;
		case KAFL_ENABLE:
			pr_warn("[*] Agent enable!\n");
			fallthrough;
		case KAFL_RESUME:
			fuzz_enabled = true;
			return;
		case KAFL_DONE:
			return kafl_agent_done();
		case KAFL_ABORT:
			return kafl_habort("kAFL got ABORT event.\n");
		case KAFL_SETCR3:
			return kafl_agent_setcr3();
		case KAFL_PAUSE:
			fuzz_enabled = false;
			return;
		case KAFL_SAFE_HALT:
			// seems like a benign implementation of once in userspace, nohz_idle() constantly calls this to halt()
			return;
		case KAFL_TRACE:
			return kafl_trace_locations();
		default:
			break;
	}

	if (!agent_initialized) {
		pr_alert("Got event %s but not initialized?!\n", kafl_event_name[e]);
		//dump_stack();
		return;
	}

	// post-init actions - abort if we see these before fuzz_initialized=true
	// Use this table to selectively raise error conditions
	switch (e) {
		case KAFL_KASAN:
		case KAFL_UBSAN:
			return kafl_raise_kasan();
		case KAFL_PANIC:
		case KAFL_ERROR:
		case KAFL_HALT:
		case KAFL_REBOOT:
			return kafl_raise_panic();
		case KAFL_TIMEOUT:
			return kafl_habort("TODO: add a timeout handler?!\n");
		default:
			return kafl_habort("Unrecognized fuzz event.\n");
	}
}

/*
 * Set verbosity of kernel to hprintf logging
 * Beyond early boot, this can be set using hprintf= cmdline
 */
//static int vprintk_level = KERN_DEBUG[1];
static int vprintk_level = KERN_WARNING[1];
//static int vprintk_level = '0'; // mute

static int __init kafl_vprintk_setup(char *str)
{
	if (str[0] >= '0' && str[0] <= '9') {
		vprintk_level = str[0];
		//hprintf("hprintf_setup: %x => %d (%d)\n", str[0], vprintk_level, vprintk_level-'0');
	}

	return 1;
}
__setup("hprintf=", kafl_vprintk_setup);

/*
 * Redirect kernel printk() to hprintf
 */
int kafl_vprintk(const char *fmt, va_list args)
{
	static int last_msg_level = 0;

	char *buf;

	if (vprintk_level == '0')
		return 0; // mute printk - kafl_hprintf() still works

	// some callers give level as arg..
	vscnprintf((char*)hprintf_buffer, HPRINTF_MAX_SIZE, fmt, args);
	buf = hprintf_buffer;

	if (buf[0] != KERN_SOH[0]) {
		kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)hprintf_buffer);
		return 0;
	}

	if (buf[1] == KERN_CONT[1]) {
		if (last_msg_level <= vprintk_level) {
			kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)buf+2);
		}
		return 0;
	}

	last_msg_level = buf[1];
	if (buf[1] <= vprintk_level) {
		kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)buf+2);
	}

	return 0;
}

#ifdef CONFIG_TDX_FUZZ_KAFL_DEBUGFS
static ssize_t control_write(struct file *f, const char __user *usr_buf,
			    size_t len, loff_t *off)
{
	char buf[256];

	if (len > 255) {
		pr_warn("Bad control input size, truncating: %ld >> %d", len, 255);
		len = 255;
	}

	buf[len] = '\0';
	len = strncpy_from_user(buf, usr_buf, len);

	if (0 == strncmp("start\n", buf, len)) {
		kafl_fuzz_event(KAFL_START);
	}
	else if (0 == strncmp("enable\n", buf, len)) {
		kafl_fuzz_event(KAFL_ENABLE);
	}
	else if (0 == strncmp("done\n", buf, len)) {
		kafl_fuzz_event(KAFL_DONE);
	}
	else if (0 == strncmp("abort\n", buf, len)) {
		kafl_fuzz_event(KAFL_ABORT);
	}
	else if (0 == strncmp("setcr3\n", buf, len)) {
		kafl_fuzz_event(KAFL_SETCR3);
	}
	else if (0 == strncmp("pause\n", buf, len)) {
		kafl_fuzz_event(KAFL_PAUSE);
	}
	else if (0 == strncmp("resume\n", buf, len)) {
		kafl_fuzz_event(KAFL_RESUME);
	}
	else if (0 == strncmp("panic\n", buf, len)) {
		kafl_fuzz_event(KAFL_PANIC);
	}
	else if (0 == strncmp("kasan\n", buf, len)) {
		kafl_fuzz_event(KAFL_KASAN);
	}
	else if (0 == strncmp("ubsan\n", buf, len)) {
		kafl_fuzz_event(KAFL_UBSAN);
	}
	else {
		pr_warn("Unrecognized event - %s", buf);
		return -EINVAL;
	}

	return len;
}

static struct file_operations control_fops = {
	.owner	 = THIS_MODULE,
	.open	 = simple_open,
	.write	 = control_write,
	.llseek  = no_llseek,
};

static int kafl_buf_get_u8(void *data, u64 *val)
{
	u8 tmp = 0;

	if (!fuzz_enabled) {
		return -EINVAL;
	}

	if (!agent_initialized) {
		kafl_agent_init();
	}
	
	if (!kafl_fuzz_buffer(&tmp, val, 0, sizeof(u8), TDX_FUZZ_DEBUGFS)) {
		pr_warn("Warning, failed to fill u8 from fuzz buffer?!");
	}
	*val = tmp;

	return 0;
}

static int kafl_buf_get_u32(void *data, u64 *val)
{
	u32 tmp = 0;

	if (!fuzz_enabled) {
		return -EINVAL;
	}

	if (!agent_initialized) {
		kafl_agent_init();
	}

	if (!kafl_fuzz_buffer(&tmp, val, 0, sizeof(u32), TDX_FUZZ_DEBUGFS)) {
		pr_warn("Warning, failed to fill u8 from fuzz buffer?!");
	}
	*val = tmp;

	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(buf_get_u8_fops, kafl_buf_get_u8, NULL, "%llu");
DEFINE_DEBUGFS_ATTRIBUTE(buf_get_u32_fops, kafl_buf_get_u32, NULL, "%llu");

static int __init kafl_debugfs_init(void)
{
	struct dentry *dbp, *statp;

	dbp = debugfs_create_dir("kafl", NULL);
	if (!dbp)
		return PTR_ERR(dbp);

	/* Don't allow verbose because printk can trigger another tdcall */
	//debugfs_remove(debugfs_lookup("verbose", dbp));
	debugfs_create_bool("fuzz_enabled",     0600, dbp, &fuzz_enabled);
	debugfs_create_bool("fuzz_tdcall",      0600, dbp, &fuzz_tdcall);
	debugfs_create_bool("fuzz_tderrors",    0600, dbp, &fuzz_tderror);
	debugfs_create_bool("exit_at_eof",      0600, dbp, &exit_at_eof);
	debugfs_create_file("control",          0600, dbp, NULL, &control_fops);
	debugfs_create_file("buf_get_u8",       0400, dbp, NULL, &buf_get_u8_fops);
	debugfs_create_file("buf_get_u32",      0400, dbp, NULL, &buf_get_u32_fops);
	debugfs_create_bool("dump_observed",    0600, dbp, &agent_flags.dump_observed);
	debugfs_create_bool("dump_stats",       0600, dbp, &agent_flags.dump_stats);
	debugfs_create_bool("dump_callers",     0600, dbp, &agent_flags.dump_callers);

	statp = debugfs_create_dir("status", dbp);
	debugfs_create_bool("running",          0400, statp, &agent_initialized);
	debugfs_create_u32("payload_size",      0400, statp, &ve_num);
	debugfs_create_u32("payload_used",      0400, statp, &ve_pos);
	debugfs_create_u32("payload_max",       0400, statp, &host_config.payload_buffer_size);
	debugfs_create_u32("bitmap_size_main",  0400, statp, &host_config.bitmap_size);
	debugfs_create_u32("bitmap_size_ijon",  0400, statp, &host_config.ijon_bitmap_size);
	debugfs_create_u32("worker_id",         0400, statp, &host_config.worker_id);
	debugfs_create_u32("stats_msr",         0400, statp, &(location_stats[TDX_FUZZ_MSR_READ]));
	debugfs_create_u32("stats_mmio",        0400, statp, &(location_stats[TDX_FUZZ_MMIO_READ]));
	debugfs_create_u32("stats_pio",         0400, statp, &(location_stats[TDX_FUZZ_PORT_IN]));
	debugfs_create_u32("stats_cpuid1",      0400, statp, &(location_stats[TDX_FUZZ_CPUID1]));
	debugfs_create_u32("stats_cpuid2",      0400, statp, &(location_stats[TDX_FUZZ_CPUID2]));
	debugfs_create_u32("stats_cpuid3",      0400, statp, &(location_stats[TDX_FUZZ_CPUID3]));
	debugfs_create_u32("stats_cpuid4",      0400, statp, &(location_stats[TDX_FUZZ_CPUID4]));
	debugfs_create_u32("stats_virtio",      0400, statp, &(location_stats[TDX_FUZZ_VIRTIO]));

	return 0;
}

__initcall(kafl_debugfs_init)
#endif
