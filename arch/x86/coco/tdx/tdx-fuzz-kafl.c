/*
 * kAFL agent for fuzzing #VE returns
 *
 * Dynamically initiate handshake + snapshot upon first use
 */

#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <asm/tdx.h>
#include <asm/trace/tdx.h>

#include <linux/pci.h>
#include <linux/msi.h>
#include <linux/of_device.h>
#include <linux/of_pci.h>
#include <linux/pci_hotplug.h>

#include <kafl_user.h>

static bool agent_initialized = false;
static bool agent_enabled = false;
static agent_config_t agent_config = {0};

static uint8_t payload_buffer[PAYLOAD_SIZE] __attribute__((aligned(4096)));
static uint8_t observed_payload_buffer[PAYLOAD_SIZE] __attribute__((aligned(4096)));
static uint32_t location_stats[TDX_FUZZ_MAX];

static u64 *ve_buf;
static u32 ve_num;
static u32 ve_pos;
static u32 ve_mis;

static u64 *ob_buf;
static u32 ob_num;
static u32 ob_pos;

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
void kafl_dump_observed_payload(char *filename, uint8_t *buf, uint32_t buflen)
{
	kafl_dump_file_t f;

	f.file_name_str_ptr = (uint64_t)filename;
	f.data_ptr = (uint64_t)buf;
	f.bytes = buflen;
	pr_info("Submit payload dump %p\n", &f);
	kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uint64_t)&f);
}

void kafl_agent_init(void)
{
	kAFL_payload* payload = (kAFL_payload*)payload_buffer;

	if (agent_initialized) {
		kafl_agent_abort("Warning: Agent was already initialized!\n");
	}

	hprintf("[*] Initialize kAFL Agent\n");

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
	memset(observed_payload_buffer, 0xff, PAYLOAD_SIZE);
	memset(payload, 0xff, PAYLOAD_SIZE);

	hprintf("Submitting payload buffer address to hypervisor (%lx)\n", payload);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)payload);

	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
	if (agent_config.dump_payloads) {
		ob_buf = (u64*)observed_payload_buffer;
		ob_num = sizeof(observed_payload_buffer)/sizeof(u64);
		ob_pos = 0;
		hprintf("Enabled dump payload (max_entries=%u)\n", ob_num);
	}

	//hprintf("Submitting current CR3 value to hypervisor...\n");
	//kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

	// set IP filter range from agent?
	//kafl_agent_setrange();

	// fetch fuzz input for later #VE injection
	hprintf("Starting kAFL loop...\n");
	kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

	ve_buf = (u64*)payload->data;
	ve_num = payload->size / sizeof(u64);
	ve_pos = 0;
	ve_mis = 0;

	memset(location_stats, 0, sizeof(location_stats));
	agent_initialized = true;

	// start coverage tracing
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 
}

void kafl_agent_done(void)
{
	unsigned i;

	hprintf("agent done!\n");

	if (!agent_initialized)
		return;

	agent_enabled = false;

	pr_info("[*] Injected %d values, missed %d.\n", ve_pos, ve_mis);
	for (i=0; i<TDX_FUZZ_MAX; i++) {
		if (location_stats[i] != 0) {
			pr_debug("\tstat[%u] = %u\n", i, location_stats[i]);
		}
	}

	// Dump observed values
	if (agent_config.dump_payloads) {
		hprintf("Dumping observed input...\n");
		kafl_dump_observed_payload("payload.txt", (uint8_t*)ob_buf, ob_pos*sizeof(ob_buf[0]));
	}

	// Stops tracing and restore the snapshot
	// Non-zero argument triggers stream_expand mutation in kAFL
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, ve_mis*sizeof(ve_buf[0]));
}

void kafl_agent_stop(void)
{
	if (!agent_enabled) {
		kafl_agent_abort("Attempt to finish kAFL run but not yet enabled\n");
	}

	if (!agent_initialized) {
		kafl_agent_abort("Attempt to finish kAFL run but never initialized\n");
	}

	kafl_agent_done();
}

u64 kafl_fuzz_var(u64 var)
{
	if (ve_pos < ve_num) {
		//pr_debug("replace %llx by %llx\n", var, ve_buf[ve_pos]);
		var = ve_buf[ve_pos];
		ve_pos++;
	}
	else {
		ve_mis++;
		// stop at end of fuzz input, unless in dump mode
		if (!agent_config.dump_payloads)
			kafl_agent_done();
	}

	if (agent_config.dump_payloads) {
		// record input seen so far
		// execution may be (have been) partly driven by fuzzer
		if (ob_pos < ob_num) {
			//hprintf("dump_payload: ob_buf[%u] = %08lx\n", ob_pos, var);
			ob_buf[ob_pos++] = var;
		} else {
			hprintf("Error: insufficient space in dump_payload");
			kafl_agent_done();
		}
	}

	return var;
}

u64 tdx_fuzz(u64 var, uintptr_t addr, int size, enum tdx_fuzz_loc loc)
{
	if (!agent_enabled) {
		return var;
	}

	if (!agent_initialized) {
		kafl_agent_init();
	}

	//hprintf("trace: val=%llx, loc=%x\n", var, loc);

	switch(loc) {
		default:
			location_stats[loc]++;
			return kafl_fuzz_var(var);
		//case TDX_FUZZ_PORT_IN:
		//case TDX_FUZZ_MSR_READ:
		//case TDX_FUZZ_MMIO_READ:
			return var;
	}
}

void tdx_fuzz_enable(void)
{
	agent_enabled = true;
	pr_debug("[*] Agent enabled.\n");
}

void tdx_fuzz_event(enum tdx_fuzz_event e)
{
	switch (e) {
		case TDX_FUZZ_PANIC:
			return kafl_raise_panic();
		case TDX_FUZZ_KASAN:
		case TDX_FUZZ_UBSAN:
			return kafl_raise_kasan();
		case TDX_FUZZ_DONE:
			//return kafl_agent_stop();
			return kafl_agent_done();
		case TDX_FUZZ_HALT:
		case TDX_FUZZ_REBOOT:
		case TDX_FUZZ_SAFE_HALT:
		case TDX_FUZZ_TIMEOUT:
			return kafl_agent_done();
		case TDX_FUZZ_DISABLE:
			hprintf("TDX_FUZZ_DISABLE agent_initialized=%d agent_enabled=%d\n", agent_initialized, agent_enabled);
			if (agent_initialized) {
				agent_enabled = false;
			}
			break;
		case TDX_FUZZ_ENABLE:
			hprintf("TDX_FUZZ_ENABLE agent_initialized=%d agent_enabled=%d\n", agent_initialized, agent_enabled);
			if (agent_initialized) {
				agent_enabled = true;
			}
			break;
		default:
			return kafl_agent_abort("Unrecognized fuzz event.");

	}
}
