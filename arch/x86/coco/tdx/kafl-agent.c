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
#include <asm/tdx.h>
#include <asm/trace/tdx.h>

#include <linux/pci.h>
#include <linux/msi.h>
#include <linux/of_device.h>
#include <linux/of_pci.h>
#include <linux/pci_hotplug.h>

#include <asm/kafl-agent.h>

#undef pr_fmt
#define pr_fmt(fmt) "kAFL: " fmt


static bool agent_initialized = false;
static bool fuzz_enabled = false;
static bool fuzz_tdcall = true;   // enable TDX fuzzing by default
static bool fuzz_tderror = false; // TDX error fuzzing not supported

/* abort at end of payload - otherwise we keep feeding unmodified input
 * which means we see coverage that is not represented in the payload */
static bool exit_at_eof = true;

static agent_config_t agent_config = {0};
static host_config_t host_config = {0};

static kafl_dump_file_t dump_file __attribute__((aligned(4096)));
static uint8_t payload_buffer[PAYLOAD_BUFFER_SIZE] __attribute__((aligned(4096)));
static uint8_t observed_payload_buffer[PAYLOAD_BUFFER_SIZE*2] __attribute__((aligned(4096)));
static uint32_t location_stats[TDX_FUZZ_MAX];

static struct {
		bool dump_observed;
		bool dump_stats;
		bool dump_callers;
} agent_flags;

static u8 *ve_buf;
static u32 ve_num;
static u32 ve_pos;
static u32 ve_mis;

static u8 *ob_buf;
static u32 ob_num;
static u32 ob_pos;

static void tdx_fuzz_filter_init(void);

void kafl_raise_panic(void) {
	kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
}

void kafl_raise_kasan(void) {
	kAFL_hypercall(HYPERCALL_KAFL_KASAN, 0);
}

void kafl_agent_setrange(void)
{
	uintptr_t ranges[3];
	ranges[0] = (uintptr_t)&pci_scan_bridge & PAGE_MASK;
	ranges[0] = (uintptr_t)&tdx_handle_virtualization_exception & PAGE_MASK;
	//ranges[0] = (uintptr_t)&fuzzme & PAGE_MASK;
	ranges[1] = ranges[0] + PAGE_SIZE;
	ranges[2] = 0;
	hprintf("Setting range %lu: %lx-%lx\n", ranges[2], ranges[0], ranges[1]);
	kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uintptr_t)ranges);
}

void kafl_agent_abort(char *msg)
{
	hprintf(msg);
	kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
	BUG();
}

static
void kafl_dump_observed_payload(char *filename, int append, uint8_t *buf, uint32_t buflen)
{
	char fname_buf[128];
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

void kafl_agent_init(void)
{
	kAFL_payload* payload = (kAFL_payload*)payload_buffer;

	if (agent_initialized) {
		kafl_agent_abort("Warning: Agent was already initialized!\n");
	}

	hprintf("[*] Initialize kAFL Agent\n");
	tdx_fuzz_filter_init();

	/* initial fuzzer handshake */
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	/* used for code injection and libxdc disassembly */
#if defined(__i386__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_32);
#elif defined(__x86_64__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
#endif

	/* ensure that the virtual memory is *really* present in physical memory... */
	memset(observed_payload_buffer, 0xff, PAYLOAD_BUFFER_SIZE);
	memset(payload, 0xff, PAYLOAD_BUFFER_SIZE);

	hprintf("Submitting payload buffer address to hypervisor (%lx)\n", payload);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)payload);

	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

	hprintf("[host_config] bitmap sizes = <0x%x,0x%x>\n", host_config.bitmap_size, host_config.ijon_bitmap_size);
	hprintf("[host_config] payload size = %dKB\n", host_config.payload_buffer_size/1024);
	hprintf("[host_config] worker id = %02u\n", host_config.worker_id);

	if (host_config.payload_buffer_size > PAYLOAD_BUFFER_SIZE) {
		kafl_agent_abort("Host agent buffer is larger than agent side allocation!\n");
	}

	// set IP filter range from agent?
	//kafl_agent_setrange();

	// fetch fuzz input for later #VE injection
	hprintf("Starting kAFL loop...\n");
	kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

	ve_buf = (u8*)payload->data;
	ve_num = payload->size / sizeof(ve_buf[0]);
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
		ob_buf = (u8*)observed_payload_buffer;
		ob_num = sizeof(observed_payload_buffer)/sizeof(ob_buf[0]);
		ob_pos = 0;
	}

	memset(location_stats, 0, sizeof(location_stats));
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
		kafl_dump_observed_payload("payload_XXXXXX", false, (uint8_t*)ob_buf, ob_pos*sizeof(ob_buf[0]));
	}

	if (agent_flags.dump_stats) {

		// flag if payload buffer is >90% and we quit due to missing input
		char maxed_out = ' ';
		if (ve_mis && MAX_PAYLOAD_LEN/10*9 < (ve_pos) * sizeof(ve_buf[0])) {
			maxed_out = '*';
		}

		ob_num = snprintf(observed_payload_buffer,
				          sizeof(observed_payload_buffer),
						  "%05u/%u: %5u, %5u, %5u;\trng=%u; cpuid=<%u,%u,%u,%u>; err=<%u,%u,%u,%u> %c\n",
				          ve_pos, ve_mis,
				          location_stats[TDX_FUZZ_MSR_READ],
				          location_stats[TDX_FUZZ_MMIO_READ],
				          location_stats[TDX_FUZZ_PORT_IN],
				          location_stats[TDX_FUZZ_RANDOM],
				          location_stats[TDX_FUZZ_CPUID1],
				          location_stats[TDX_FUZZ_CPUID2],
				          location_stats[TDX_FUZZ_CPUID3],
				          location_stats[TDX_FUZZ_CPUID4],
						  location_stats[TDX_FUZZ_MSR_READ_ERR],
						  location_stats[TDX_FUZZ_MSR_WRITE_ERR],
						  location_stats[TDX_FUZZ_MAP_ERR],
						  location_stats[TDX_FUZZ_PORT_IN_ERR],
						  maxed_out);
		pr_debug("Dumping fuzzer location stats\n");
		kafl_dump_observed_payload("fuzzer_location_stats.lst", true,
			   observed_payload_buffer, ob_num);
	}
}

void kafl_agent_done(void)
{
	if (!agent_initialized) {
		kafl_agent_abort("Attempt to finish kAFL run but never initialized\n");
	}

	kafl_agent_stats();

	// Stops tracing and restore the snapshot for next round
	// Non-zero argument triggers stream_expand mutation in kAFL
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, ve_mis*sizeof(ve_buf[0]));
}

u64 kafl_fuzz_var(u64 var, int num_bytes)
{
	if (ve_pos + num_bytes <= ve_num) {
		while (num_bytes--)
			var = (var << 8) ^ ve_buf[ve_pos++];
	}
	else {
		ve_mis++;
		if (exit_at_eof && !agent_flags.dump_observed)
			kafl_agent_done();
	}

	return var;
}

char *tdx_fuzz_loc_str[] = {
	"MSR",
	"MIO",
	"ERR_RMSR",
	"ERR_WMSR",
	"ERR_MMAP",
	"PIO",
	"ERR_PIO",
	"CPUID1",
	"CPUID2",
	"CPUID3",
	"CPUID4",
	"RNG",
};

u64 tdx_fuzz(u64 orig_var, uintptr_t addr, int size, enum tdx_fuzz_loc type)
{
	u64 var;

	if (!fuzz_enabled || !fuzz_tdcall) {
		// for filtering stimulus payloads, raise a trace event with size=0 here
		trace_tdx_fuzz((u64)__builtin_return_address(0), 0, orig_var, orig_var, type);
		return orig_var;
	}

	// skip any fuzzing blockers
	switch(type) {
		//case TDX_FUZZ_PORT_IN:
		//case TDX_FUZZ_MSR_READ:
#ifdef CONFIG_TDX_FUZZ_KAFL_SKIP_RNG_SEEDING
		case TDX_FUZZ_RANDOM:
			return 42;
#endif
#ifdef CONFIG_TDX_FUZZ_KAFL_SKIP_ACPI_PIO
		case TDX_FUZZ_PORT_IN:
			/*
			 * Multiple relevant PIO regions, may have to activate depending on target
			 * e.g. https://qemu.readthedocs.io/en/latest/specs/acpi_pci_hotplug.html
			 */
			if ((addr >= 0xb000 && addr <= 0xb006) || // ACPI init?
			    (addr >= 0xafe0 && addr <= 0xafe2)) { // ACPI PCI hotplug
				return orig_var;
			}
			break;
#endif
#ifdef CONFIG_TDX_FUZZ_KAFL_SKIP_IOAPIC_READS
		case TDX_FUZZ_MMIO_READ:
			if (addr == 0xfec00000 || addr == 0xfec00010) {
				return orig_var;
			}
			break;
#endif
#ifdef CONFIG_TDX_FUZZ_KAFL_SKIP_CPUID
		case TDX_FUZZ_CPUID1:
		case TDX_FUZZ_CPUID2:
		case TDX_FUZZ_CPUID3:
		case TDX_FUZZ_CPUID4:
			return orig_var;
#endif
		default:
			; // continue to fuzzing
	}

	if (!agent_initialized) {
		kafl_agent_init();
	}

	location_stats[type]++;
	var = kafl_fuzz_var(orig_var, size);
	
	trace_tdx_fuzz((u64)__builtin_return_address(0), size, orig_var, var, type);

	if (agent_flags.dump_callers) {
		printk(KERN_WARNING "\nfuzz_var: %s[%d], addr: %16lx, orig: %16llx, isr: %lx\n",
				tdx_fuzz_loc_str[type], size, addr, orig_var, in_interrupt());
		dump_stack();
	}

	if (agent_flags.dump_observed) {
		// record input seen so far
		// execution may be (have been) partly driven by fuzzer
		int num_bytes = size;
		u8 *pvar = (u8*)&var;
		if (ob_pos <= ob_num - num_bytes) {
			while (num_bytes) {
				// TODO: debug KASAN null-ptr-deref around here?!
				BUG_ON(!ob_buf);
				BUG_ON(!pvar);
				if (ob_buf && pvar) {
					ob_buf[ob_pos++] = pvar[sizeof(var)-num_bytes];
				}
				num_bytes--;
			}
		} else {
			pr_warn("Warning: insufficient space in dump_payload\n");
			kafl_agent_done();
		}
	}

	return var;
}

bool tdx_fuzz_err(enum tdx_fuzz_loc type)
{
	if (!fuzz_enabled || !fuzz_tderror) {
		// for filtering stimulus payloads, raise a trace event with size=0 here
		trace_tdx_fuzz((u64)__builtin_return_address(0), 0, 1, 1, type);
		return false;
	}
	
	trace_tdx_fuzz((u64)__builtin_return_address(0), 1, 0, 1, type);
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


static int kp_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	pr_debug("pause fuzzing for %s\n", p->symbol_name);
	tdx_fuzz_event(TDX_FUZZ_PAUSE);
	return 0;
}

static void kp_handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	// TODO: check if it should be enabled
	tdx_fuzz_event(TDX_FUZZ_RESUME);
}

#define TDX_MAX_NUM_KPROBES 16
static struct kprobe tdx_kprobes[TDX_MAX_NUM_KPROBES] = {0};
static int tdx_kprobes_n = 0;

static void tdx_fuzz_filter_init(void)
{
	int ret;

	struct disallowlist_entry *entry;
	struct kprobe *kp;

	list_for_each_entry(entry, &disallowed_fuzzing_calls, next) {
		pr_info("disable fuzzing mutation for %s\n", entry->buf);
		//struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
		if (tdx_kprobes_n >= TDX_MAX_NUM_KPROBES) {
			pr_info("%s: max number of probes reached (%d)\n", __func__, tdx_kprobes_n);
			return;
		}
		kp = &tdx_kprobes[tdx_kprobes_n++];
		kp->symbol_name = entry->buf;
		//kp->addr = &fork_init;
		kp->pre_handler = kp_handler_pre;
		kp->post_handler = kp_handler_post;
		ret = register_kprobe(kp);
		if (ret < 0) {
			pr_info("register_kprobe failed, returned %d\n", ret);
			continue;
		}
		ret = enable_kprobe(kp);
		if (ret < 0) {
			pr_info("enable_kprobe failed, returned %d\n", ret);
			continue;
		}
		pr_info("Planted kprobe at %lx\n", (uintptr_t)kp->addr);
	}

}

void tdx_fuzz_event(enum tdx_fuzz_event e)
{
	// pre-init actions
	switch (e) {
		case TDX_FUZZ_START:
			pr_warn("[*] Agent start!\n");
			kafl_agent_init();
			fuzz_enabled = true;
			return;
		case TDX_FUZZ_ENABLE:
			pr_warn("[*] Agent enable!\n");
			fuzz_enabled = true;
			return;
		case TDX_FUZZ_DONE:
			return kafl_agent_done();
		case TDX_FUZZ_ABORT:
			return kafl_agent_abort("kAFL got ABORT event.\n");
		case TDX_FUZZ_SETCR3:
			return kafl_agent_setcr3();
		case TDX_FUZZ_PAUSE:
			if (agent_initialized) {
				fuzz_enabled = false;
			}
			break;
		case TDX_FUZZ_RESUME:
			if (agent_initialized) {
				fuzz_enabled = true;
			}
			break;
		default:
			//return kafl_agent_abort("Unrecognized fuzz event.\n");
			break;
	}

	// once in userspace, nohz_idle() constantly calls this to halt()
	if (e == TDX_FUZZ_SAFE_HALT)
		return;

	if (!agent_initialized) {
		pr_alert("Got event %x but not initialized?!\n", e);
		dump_stack();
		return;
	}

	// select here what kind of errors to raise to fuzzer
	switch (e) {
		case TDX_FUZZ_KASAN:
		case TDX_FUZZ_UBSAN:
			return kafl_raise_kasan();
		case TDX_FUZZ_PANIC:
		case TDX_FUZZ_ERROR:
		case TDX_FUZZ_HALT:
		case TDX_FUZZ_REBOOT:
		case TDX_FUZZ_SAFE_HALT:
			return kafl_raise_panic();
		case TDX_FUZZ_TIMEOUT:
			return kafl_agent_abort("TODO: add a timeout handler?!\n");
		default:
			return kafl_agent_abort("Unrecognized fuzz event.\n");
	}
}

#ifdef CONFIG_TDX_FUZZ_KAFL_DEBUGFS
static ssize_t control_write(struct file *f, const char __user *buf,
			    size_t len, loff_t *off)
{
	if (0 == strncmp("start\n", buf, len)) {
		tdx_fuzz_event(TDX_FUZZ_START);
	}
	else if (0 == strncmp("enable\n", buf, len)) {
		tdx_fuzz_event(TDX_FUZZ_ENABLE);
	}
	else if (0 == strncmp("done\n", buf, len)) {
		tdx_fuzz_event(TDX_FUZZ_DONE);
	}
	else if (0 == strncmp("abort\n", buf, len)) {
		tdx_fuzz_event(TDX_FUZZ_ABORT);
	}
	else if (0 == strncmp("setcr3\n", buf, len)) {
		tdx_fuzz_event(TDX_FUZZ_SETCR3);
	}
	else if (0 == strncmp("pause\n", buf, len)) {
		tdx_fuzz_event(TDX_FUZZ_PAUSE);
	}
	else if (0 == strncmp("resume\n", buf, len)) {
		tdx_fuzz_event(TDX_FUZZ_RESUME);
	}
	else if (0 == strncmp("panic\n", buf, len)) {
		tdx_fuzz_event(TDX_FUZZ_PANIC);
	}
	else if (0 == strncmp("kasan\n", buf, len)) {
		tdx_fuzz_event(TDX_FUZZ_KASAN);
	}
	else if (0 == strncmp("ubsan\n", buf, len)) {
		tdx_fuzz_event(TDX_FUZZ_UBSAN);
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

static int buf_get_u8(void *data, u64 *val)
{
	if (!fuzz_enabled) {
		return -EINVAL;
	}

	if (!agent_initialized) {
		kafl_agent_init();
	}
	
	*val = kafl_fuzz_var(*val, sizeof(u8)) & 0xFF;

	return 0;
}

static int buf_get_u32(void *data, u64 *val)
{
	//int num = sizeof(u32);

	if (!fuzz_enabled) {
		return -EINVAL;
	}

	if (!agent_initialized) {
		kafl_agent_init();
	}

	*val = kafl_fuzz_var(*val, sizeof(u32)) & 0xFFFFFFFF;

	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(buf_get_u8_fops, buf_get_u8, NULL, "%llu");
DEFINE_DEBUGFS_ATTRIBUTE(buf_get_u32_fops, buf_get_u32, NULL, "%llu");

static int __init tdx_fuzz_init(void)
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

	statp = debugfs_create_dir("status", dbp);
	debugfs_create_bool("running",          0400, statp, &agent_initialized);
	debugfs_create_u32("payload_size",      0400, statp, &ve_num);
	debugfs_create_u32("payload_used",      0400, statp, &ve_pos);
	debugfs_create_u32("payload_max",       0400, statp, &host_config.payload_buffer_size);
	debugfs_create_u32("bitmap_size_main",  0400, statp, &host_config.bitmap_size);
	debugfs_create_u32("bitmap_size_ijon",  0400, statp, &host_config.ijon_bitmap_size);
	debugfs_create_u32("worker_id",        0400, statp, &host_config.worker_id);
	debugfs_create_u32("stats_msr",         0400, statp, &(location_stats[TDX_FUZZ_MSR_READ]));
	debugfs_create_u32("stats_mmio",        0400, statp, &(location_stats[TDX_FUZZ_MMIO_READ]));
	debugfs_create_u32("stats_pio",         0400, statp, &(location_stats[TDX_FUZZ_PORT_IN]));
	debugfs_create_u32("stats_cpuid1",      0400, statp, &(location_stats[TDX_FUZZ_CPUID1]));
	debugfs_create_u32("stats_cpuid2",      0400, statp, &(location_stats[TDX_FUZZ_CPUID2]));
	debugfs_create_u32("stats_cpuid3",      0400, statp, &(location_stats[TDX_FUZZ_CPUID3]));
	debugfs_create_u32("stats_cpuid4",      0400, statp, &(location_stats[TDX_FUZZ_CPUID4]));
	debugfs_create_bool("flags_observed",   0400, statp, &agent_flags.dump_observed);
	debugfs_create_bool("flags_stats",      0400, statp, &agent_flags.dump_stats);
	debugfs_create_bool("flags_callers",    0400, statp, &agent_flags.dump_callers);

	return 0;
}

__initcall(tdx_fuzz_init)
#endif
