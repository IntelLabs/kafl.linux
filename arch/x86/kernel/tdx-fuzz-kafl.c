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

bool virtio_fuzz_enabled = false;
static bool agent_initialized = false;
static bool agent_enabled = false;

static uint8_t payload_buffer[PAYLOAD_SIZE] __attribute__((aligned(4096)));
static uint32_t location_stats[TDX_FUZZ_MAX];
	
static u64 *ve_buf;
static u32 ve_num;
static u32 ve_pos;
static u32 ve_mis;

void kafl_setrange(void)
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

void agent_init(void)
{
	void* panic_handler = 0;
	void* printk_handler = 0;
	void* kasan_handler = 0;
	kAFL_payload* payload = (kAFL_payload*)payload_buffer;

	if (!agent_enabled)
		return;

	hprintf("[*] Initiate kAFL Agent\n");
	//WARN_ON(1);

	printk_handler = (void*)&_printk;
	hprintf("Kernel Print Handler Address:\t%lx\n", (uintptr_t)printk_handler);
	
	panic_handler = (void*)&panic;
	hprintf("Kernel Panic Handler Address:\t%lx\n", (uintptr_t)panic_handler);

	//kasan_handler = (void*)&kasan_report_error;
	if (kasan_handler){
		hprintf("Kernel KASan Handler Address:\t%lx\n", (uintptr_t)kasan_handler);
	}
	
	/* initial fuzzer handshake */
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	/* used for code injection and libxdc disassembly */
#if defined(__i386__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_32);
#elif defined(__x86_64__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
#endif

	/* submit function pointers for override by Qemu/kAFL */
	//kAFL_hypercall(HYPERCALL_KAFL_PRINTK_ADDR, (uintptr_t)printk_handler);
	//kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, (uintptr_t)panic_handler);
	if (kasan_handler){
		kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, (uintptr_t)kasan_handler);
	}

	/* ensure that the virtual memory is *really* present in physical memory... */
	memset(payload, 0xff, PAYLOAD_SIZE);

	hprintf("Submitting buffer address to hypervisor (%lx)\n", payload);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)payload);
	//hprintf("Submitting current CR3 value to hypervisor...\n");
	//kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

	// set IP filter range from agent?
	//kafl_setrange();

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

u64 __tdx_fuzz(u64 var)
{
	if (ve_pos < ve_num) {
		//hprintf("replace %llx by %llx\n", var, ve_buf[ve_pos]);
		var = ve_buf[ve_pos];
		ve_pos++;
	}
	else {
		ve_mis++;
		tdx_fuzz_finish(); // abort at end of fuzz input?
	}
	return var;
}

u64 tdx_fuzz(u64 var, uintptr_t addr, int size, enum tdx_fuzz_loc loc)
{
	if (!agent_enabled) {
		return var;
	}

	if (!agent_initialized) {
		agent_init();
	}

	//hprintf("trace: val=%llx, loc=%x\n", var, loc);

	switch(loc) {
		default:
			location_stats[loc]++;
			return __tdx_fuzz(var);
		//case TDX_FUZZ_PORT_IN:
		//case TDX_FUZZ_MSR_READ:
		//case TDX_FUZZ_MMIO_READ:
			return var;
	}
}

void tdx_fuzz_enable()
{
	if (agent_enabled) {
		hprintf("WARNING: Agent was already enabled..\n");
		kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
		BUG();
	}
	agent_enabled = true;
	hprintf("[*] Agent enabled.\n");
}

void tdx_fuzz_finish()
{
	if (!agent_enabled) {
		hprintf("Attempt to finish kAFL run but not yet enabled\n");
		kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
		BUG();
	}
	if (!agent_initialized) {
		hprintf("Attempt to finish kAFL run but never initialized\n");
		kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
		BUG();
	}

	agent_enabled = false;

	hprintf("[*] Injected %d values, missed %d.\n", ve_pos, ve_mis);
	//unsigned i;
	//for (i=0; i<TDX_FUZZ_MAX; i++) {
	//	if (location_stats[i] != 0) {
	//		hprintf("\tstat[%u] = %lu\n", i, location_stats[i]);
	//	}
	//}

	// Stops tracing and restore the snapshot
	// Non-zero argument triggers stream_expand mutation in kAFL
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, ve_mis*sizeof(ve_buf[0]));
}
