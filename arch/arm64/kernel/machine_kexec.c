/*
 * kexec for arm64
 *
 * Copyright (C) Linaro.
 * Copyright (C) Huawei Futurewei Technologies.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/libfdt_env.h>
#include <linux/memblock.h>
#include <linux/of_fdt.h>
#include <linux/uaccess.h>
#include <linux/page-flags.h>
#include <linux/smp.h>

#include <asm/cacheflush.h>
#include <asm/cpu_ops.h>
#include <asm/memory.h>
#include <asm/mmu.h>
#include <asm/mmu_context.h>
#include <asm/page.h>

#include "cpu-reset.h"

#ifdef CONFIG_KEXEC_HARDBOOT
#include <asm/kexec.h>
#endif

/* Bypass purgatory for debugging. */
static const int bypass_purgatory = 1;

/* Global variables for the arm64_relocate_new_kernel routine. */
extern const unsigned char arm64_relocate_new_kernel[];
extern const unsigned long arm64_relocate_new_kernel_size;
extern unsigned long arm64_kexec_dtb_addr;
extern unsigned long arm64_kexec_kimage_head;
extern unsigned long arm64_kexec_kimage_start;
#ifdef CONFIG_KEXEC_HARDBOOT
extern unsigned long arm64_kexec_hardboot;
void (*kexec_hardboot_hook)(void);
#endif

/**
 * kexec_is_kernel - Helper routine to check the kernel header signature.
 */
static bool kexec_is_kernel(const void *image)
{
	struct arm64_image_header {
		uint8_t pe_sig[2];
		uint16_t branch_code[3];
		uint64_t text_offset;
		uint64_t image_size;
		uint8_t flags[8];
		uint64_t reserved_1[3];
		uint8_t magic[4];
		uint32_t pe_header;
	} h;
        if (copy_from_user(&h, image, sizeof(struct arm64_image_header)))
		return false;
	if (!h.text_offset)
		return false;
	return (h.magic[0] == 'A'
		&& h.magic[1] == 'R'
		&& h.magic[2] == 'M'
		&& h.magic[3] == 0x64U);
}
/**
 * kexec_find_kernel_seg - Helper routine to find the kernel segment.
 */
static const struct kexec_segment *kexec_find_kernel_seg(
	const struct kimage *kimage)
{
	int i;
	for (i = 0; i < kimage->nr_segments; i++) {
		if (kexec_is_kernel(kimage->segment[i].buf))
			return &kimage->segment[i];
	}
	pr_err("No kernel segment found!\n");
	return NULL;
}

/**
 * kexec_is_dtb - Helper routine to check the device tree header signature.
 */
static bool kexec_is_dtb(const void *dtb)
{
	__be32 magic;
	if (get_user(magic, (__be32 *)dtb))
		return false;

	return fdt32_to_cpu(magic) == OF_DT_HEADER;
}


/**
 * kexec_find_dtb_seg - Helper routine to find the dtb segment.
 */
static const struct kexec_segment *kexec_find_dtb_seg(
	const struct kimage *kimage)
{
	int i;
	for (i = 0; i < kimage->nr_segments; i++) {
		if (kexec_is_dtb(kimage->segment[i].buf))
			return &kimage->segment[i];
	}
	pr_err("No DTB segment found!\n");
	return NULL;
}

static struct bypass {
	unsigned long kernel;
	unsigned long dtb;
} bypass;

static void fill_bypass(const struct kimage *kimage)
{
	const struct kexec_segment *seg;
	pr_info("%s: finding kernel seg\n", __func__);
	seg = kexec_find_kernel_seg(kimage);
	if (!seg || !seg->mem) {
		pr_err("%s: no kernel segment, bypass disabled\n", __func__);
		bypass.kernel = 0;
		bypass.dtb = 0;
		return;
	}
	bypass.kernel = seg->mem;
	pr_info("%s: kernel=0x%lx, finding dtb seg\n", __func__, seg->mem);
	seg = kexec_find_dtb_seg(kimage);
	if (!seg || !seg->mem) {
		pr_err("%s: no dtb segment, bypass disabled\n", __func__);
		bypass.kernel = 0;
		bypass.dtb = 0;
		return;
	}
	bypass.dtb = seg->mem;
	pr_info("%s: kernel: %016lx dtb: %016lx\n", __func__,
		bypass.kernel, bypass.dtb);
}

/**
 * kexec_image_info - For debugging output.
 */
#define kexec_image_info(_i) _kexec_image_info(__func__, __LINE__, _i)
static void _kexec_image_info(const char *func, int line,
	const struct kimage *kimage)
{
	unsigned long i;

	pr_debug("%s:%d:\n", func, line);
	pr_debug("  kexec kimage info:\n");
	pr_debug("    type:        %d\n", kimage->type);
	pr_debug("    start:       %lx\n", kimage->start);
	pr_debug("    head:        %lx\n", kimage->head);
	pr_debug("    nr_segments: %lu\n", kimage->nr_segments);

	for (i = 0; i < kimage->nr_segments; i++) {
		pr_debug("      segment[%lu]: %016lx - %016lx, 0x%lx bytes, %lu pages\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE);
	}
}

void machine_kexec_cleanup(struct kimage *kimage)
{
	/* Empty routine needed to avoid build errors. */
}

/**
 * machine_kexec_prepare - Prepare for a kexec reboot.
 *
 * Called from the core kexec code when a kernel image is loaded.
 * Forbid loading a kexec kernel if we have no way of hotplugging cpus or cpus
 * are stuck in the kernel. This avoids a panic once we hit machine_kexec().
 */
int machine_kexec_prepare(struct kimage *kimage)
{
	unsigned long *hardboot_page;
	kexec_image_info(kimage);
	pr_info("machine_kexec_prepare: start\n");
	fill_bypass(kimage);
	pr_info("machine_kexec_prepare: after fill_bypass\n");
	if (bypass_purgatory) {
		arm64_kexec_kimage_start = bypass.kernel;
		arm64_kexec_dtb_addr = bypass.dtb;
		pr_info("machine_kexec_prepare: bypass, kernel=%lx dtb=%lx\n",
			bypass.kernel, bypass.dtb);
	} else {
		arm64_kexec_kimage_start = kimage->start;
#ifdef CONFIG_KEXEC_HARDBOOT
		if (kimage->hardboot) {
			arm64_kexec_dtb_addr = bypass.dtb;
			pr_info("machine_kexec_prepare: hardboot, kernel=%lx dtb=%lx\n",
				bypass.kernel, bypass.dtb);
		} else
#endif
			arm64_kexec_dtb_addr = 0;
	}

#ifdef CONFIG_KEXEC_HARDBOOT
	arm64_kexec_hardboot = kimage->hardboot;
	pr_info("machine_kexec_prepare: hardboot=%d\n", kimage->hardboot);

	/*
	 * Check last hardboot status, skip if ioremap fails (e.g.
	 * KEXEC_HB_PAGE is a no-map reserved region not yet mapped).
	 */
	hardboot_page = ioremap(KEXEC_HB_PAGE_ADDR, SZ_1M);
	if (hardboot_page) {
		pr_info("Last hardboot status: %lx\n", hardboot_page[0]);
		iounmap(hardboot_page);
	}
#endif
	if (kimage->type != KEXEC_TYPE_CRASH && cpus_are_stuck_in_kernel()) {
		pr_err("Can't kexec: CPUs are stuck in the kernel.\n");
		return -EBUSY;
	}

	return 0;
}

/**
 * kexec_list_flush - Helper to flush the kimage list and source pages to PoC.
 */
static void kexec_list_flush(struct kimage *kimage)
{
	kimage_entry_t *entry;

	for (entry = &kimage->head; ; entry++) {
		unsigned int flag;
		void *addr;

		/* flush the list entries. */
		__flush_dcache_area(entry, sizeof(kimage_entry_t));

		flag = *entry & IND_FLAGS;
		if (flag == IND_DONE)
			break;

		addr = phys_to_virt(*entry & PAGE_MASK);

		switch (flag) {
		case IND_INDIRECTION:
			/* Set entry point just before the new list page. */
			entry = (kimage_entry_t *)addr - 1;
			break;
		case IND_SOURCE:
			/* flush the source pages. */
			__flush_dcache_area(addr, PAGE_SIZE);
			break;
		case IND_DESTINATION:
			break;
		default:
			BUG();
		}
	}
}

#ifdef CONFIG_KEXEC_HARDBOOT
/**
 * kexec_list_hardboot_create_post_reboot_list -
 * modify existing destination list to copy kernel to temp region;
 * create new destination list in hardboot page to copy from temp region
 * to final location
 */
static void kexec_list_hardboot_create_post_reboot_list(
	unsigned long kimage_head, unsigned long *newlist_start,
	unsigned long tempdest_phys)
{
	/* so the entries are in the format:
	 * IND_DESTINATION -> where to go
	 * IND_SOURCE -> where to read one page
	 * IND_SOURCE -> where to read the next page (and so on)
	 * For existing: rewrite IND_DESTINATION to store to temp location; leave IND_SOURCE intact
	 * For new: copy original IND_DESTINATION, rewrite new IND_SOURCE to read from temp location
	 * We do not copy indirection (new list will be flat)
	 */
	void *dest;
	unsigned long *entry;
	unsigned long *newlist = newlist_start;
	for (entry = &kimage_head, dest = NULL; ; entry++) {
		unsigned int flag = *entry &
			(IND_DESTINATION | IND_INDIRECTION | IND_DONE |
			IND_SOURCE);
		void *addr = phys_to_virt(*entry & PAGE_MASK);
		switch (flag) {
		case IND_INDIRECTION:
			entry = (unsigned long *)addr - 1;
			break;
		case IND_DESTINATION:
			// new list: copy original IND_DESTINATION
			*newlist++ = *entry;
			// old list: rewrite to store to temp location
			*entry = flag | tempdest_phys;
			break;
		case IND_SOURCE:
			// new list: rewrite to read from temp location
			*newlist++ = flag | tempdest_phys;
			// new list: add to new temp destination address
			tempdest_phys += PAGE_SIZE;
			break;
		case IND_DONE:
			*newlist++ = *entry; // new list: copy original IND_DONE
			return;
		default:
			BUG();
		}
	}
}
#endif

/**
 * kexec_segment_flush - Helper to flush the kimage segments to PoC.
 */
static void kexec_segment_flush(const struct kimage *kimage)
{
	unsigned long i;

	pr_debug("%s:\n", __func__);

	for (i = 0; i < kimage->nr_segments; i++) {
		pr_debug("  segment[%lu]: %016lx - %016lx, 0x%lx bytes, %lu pages\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE);

		__flush_dcache_area(phys_to_virt(kimage->segment[i].mem),
			kimage->segment[i].memsz);
	}
}

/**
 * machine_kexec - Do the kexec reboot.
 *
 * Called from the core kexec code for a sys_reboot with LINUX_REBOOT_CMD_KEXEC.
 */
void machine_kexec(struct kimage *kimage)
{
	phys_addr_t reboot_code_buffer_phys;
	void *reboot_code_buffer;
	bool in_kexec_crash = (kimage == kexec_crash_image);
	bool stuck_cpus = cpus_are_stuck_in_kernel();

	/*
	 * New cpus may have become stuck_in_kernel after we loaded the image.
	 * For hardboot, skip the online-CPU check since warm reset will
	 * cleanly restart all cores anyway.
	 */
	if (!kimage->hardboot)
		BUG_ON(!in_kexec_crash && (stuck_cpus || (num_online_cpus() > 1)));
	WARN(in_kexec_crash && (stuck_cpus || smp_crash_stop_failed()),
		"Some CPUs may be stale, kdump will be unreliable.\n");

	arm64_kexec_kimage_head = kimage->head;
	reboot_code_buffer_phys = page_to_phys(kimage->control_code_page);
	reboot_code_buffer = phys_to_virt(reboot_code_buffer_phys);

	kexec_image_info(kimage);

	pr_debug("%s:%d: control_code_page:        %p\n", __func__, __LINE__,
		kimage->control_code_page);
	pr_debug("%s:%d: reboot_code_buffer_phys:  %pa\n", __func__, __LINE__,
		&reboot_code_buffer_phys);
	pr_debug("%s:%d: reboot_code_buffer:       %p\n", __func__, __LINE__,
		reboot_code_buffer);
	pr_debug("%s:%d: relocate_new_kernel:      %p\n", __func__, __LINE__,
		arm64_relocate_new_kernel);
	pr_debug("%s:%d: relocate_new_kernel_size: 0x%lx(%lu) bytes\n",
		__func__, __LINE__, arm64_relocate_new_kernel_size,
		arm64_relocate_new_kernel_size);

	pr_debug("%s:%d: kexec_dtb_addr:           %ld\n", __func__, __LINE__,
		arm64_kexec_dtb_addr);
	pr_debug("%s:%d: kexec_kimage_head:        %ld\n", __func__, __LINE__,
		arm64_kexec_kimage_head);
	pr_debug("%s:%d: kexec_kimage_start:       %ld\n", __func__, __LINE__,
		arm64_kexec_kimage_start);

	/*
	 * Copy arm64_relocate_new_kernel to the reboot_code_buffer for use
	 * after the kernel is shut down.
	 *
	 * For hardboot: we copy the kernel to temp space in C code (MMU on),
	 * write magic to hardboot page, then use the PMIC/SCM hook for a
	 * proper warm reset. After reboot, head.S finds the magic and jumps
	 * to the post-reboot relocator at hardboot_page+4KB, which copies
	 * from temp space back to final destinations and boots the kernel.
	 */
#ifdef CONFIG_KEXEC_HARDBOOT
	if (kimage->hardboot) {
		unsigned long hardboot_reserve = KEXEC_HB_PAGE_ADDR;
		void *hardboot_map = ioremap(hardboot_reserve, SZ_1M);
		void *post_reboot_code_buffer;
		unsigned long post_reboot_list_loc;
		unsigned long *hardboot_list_loc_virt;
		unsigned long tempdest;
		unsigned long *entry;
		void *dest = NULL;

		if (!hardboot_map) {
			pr_err("Hardboot: ioremap failed for 0x%lx\n",
				hardboot_reserve);
			/* Fall back to normal kexec - copy relocator code */
			memcpy(reboot_code_buffer, arm64_relocate_new_kernel,
				arm64_relocate_new_kernel_size);
			__flush_dcache_area(reboot_code_buffer,
				arm64_relocate_new_kernel_size);
			flush_icache_range((uintptr_t)reboot_code_buffer,
				(uintptr_t)reboot_code_buffer +
				arm64_relocate_new_kernel_size);
			goto hardboot_skip;
		}
		post_reboot_code_buffer = hardboot_map + PAGE_SIZE;
		post_reboot_list_loc = hardboot_reserve + (PAGE_SIZE * 2);
		hardboot_list_loc_virt = hardboot_map + (PAGE_SIZE * 2);
		tempdest = memblock_end_of_DRAM() - (SZ_1M * 64);

		/* Verify hardboot page is readable/writable */
		{
			unsigned long test_val;
			test_val = readl_relaxed(hardboot_map);
			writel_relaxed(test_val, hardboot_map);
		}

		// Step 1: modify original list and create post-reboot list
		kexec_list_hardboot_create_post_reboot_list(kimage->head,
			hardboot_list_loc_virt, tempdest);

		// Step 2: walk the modified list and copy kernel to temp space
		pr_info("Hardboot: copying kernel to temp space 0x%lx\n",
			tempdest);
		for (entry = &kimage->head; ; entry++) {
			unsigned int flag = *entry &
				(IND_DESTINATION | IND_INDIRECTION |
				 IND_DONE | IND_SOURCE);
			void *addr = phys_to_virt(*entry & PAGE_MASK);

			switch (flag) {
			case IND_INDIRECTION:
				entry = (unsigned long *)addr - 1;
				break;
			case IND_DESTINATION:
				dest = addr;
				break;
			case IND_SOURCE:
				memcpy(dest, addr, PAGE_SIZE);
				dest += PAGE_SIZE;
				break;
			case IND_DONE:
				goto hardboot_done;
			}
		}
hardboot_done:
		pr_info("Hardboot: copy done, setting up hardboot page\n");

		// Step 3: write magic + entry + dtb to hardboot page
		{
			unsigned long *hb = (unsigned long *)hardboot_map;
			hb[0] = KEXEC_HB_PAGE_MAGIC;
			hb[1] = arm64_kexec_kimage_start;
			hb[2] = arm64_kexec_dtb_addr;
		}

		// Step 4: setup post-reboot relocator
		arm64_kexec_kimage_head = IND_INDIRECTION | post_reboot_list_loc;
		arm64_kexec_hardboot = 0;
		memcpy(post_reboot_code_buffer, arm64_relocate_new_kernel,
			arm64_relocate_new_kernel_size);

		// Step 5: flush everything
		__flush_dcache_area(hardboot_map, SZ_1M);
		flush_icache_range((uintptr_t)post_reboot_code_buffer,
			(uintptr_t)post_reboot_code_buffer +
			arm64_relocate_new_kernel_size);

		iounmap(hardboot_map);

		// Step 6: call the PMIC/SCM hook to trigger warm reset
		pr_info("Hardboot: triggering warm reset\n");
		if (kexec_hardboot_hook)
			kexec_hardboot_hook();

		// If hook returns, fall through to standard reboot path
		pr_info("Hardboot: hook returned, falling back\n");
		memcpy(reboot_code_buffer, arm64_relocate_new_kernel,
			arm64_relocate_new_kernel_size);
		__flush_dcache_area(reboot_code_buffer,
			arm64_relocate_new_kernel_size);
		flush_icache_range((uintptr_t)reboot_code_buffer,
			(uintptr_t)reboot_code_buffer +
			arm64_relocate_new_kernel_size);
	} else
#endif
	{
		memcpy(reboot_code_buffer, arm64_relocate_new_kernel,
			arm64_relocate_new_kernel_size);
		__flush_dcache_area(reboot_code_buffer,
			arm64_relocate_new_kernel_size);
		flush_icache_range((uintptr_t)reboot_code_buffer,
			(uintptr_t)reboot_code_buffer +
			arm64_relocate_new_kernel_size);
	}

#ifdef CONFIG_KEXEC_HARDBOOT
hardboot_skip:
#endif

	/* Flush the kimage list and its buffers. */
	kexec_list_flush(kimage);

	/* Flush the new image if already in place. */
	if ((kimage != kexec_crash_image) && (kimage->head & IND_DONE))
		kexec_segment_flush(kimage);

	pr_info("Bye!\n");

	/* Disable all DAIF exceptions. */
	asm volatile ("msr daifset, #0xf" : : : "memory");

	/*
	 * cpu_soft_restart will shutdown the MMU, disable data caches, then
	 * transfer control to the reboot_code_buffer which contains a copy of
	 * the arm64_relocate_new_kernel routine.  arm64_relocate_new_kernel
	 * uses physical addressing to relocate the new image to its final
	 * position and transfers control to the image entry point when the
	 * relocation is complete.
	 */

	cpu_soft_restart_kexec(kimage != kexec_crash_image,
		reboot_code_buffer_phys, kimage->head, kimage->start, 0);

	BUG(); /* Should never get here. */
}

#ifdef CONFIG_KEXEC_HARDBOOT
bool arch_kexec_is_hardboot_buffer_range(unsigned long start,
	unsigned long end) {
	unsigned long hardboot_reserve = KEXEC_HB_PAGE_ADDR;
	unsigned long tempdest = memblock_end_of_DRAM() - (SZ_1M * 64);

	/* hardboot page area: 1MB at KEXEC_HB_PAGE_ADDR */
	if (start < hardboot_reserve + SZ_1M && end > hardboot_reserve)
		return true;

	/* temp space area: 64MB at DRAM_END - 64MB */
	if (start < tempdest + (SZ_1M * 64) && end > tempdest)
		return true;

	return false;
}
#endif

static void machine_kexec_mask_interrupts(void)
{
	unsigned int i;
	struct irq_desc *desc;

	for_each_irq_desc(i, desc) {
		struct irq_chip *chip;
		int ret;

		chip = irq_desc_get_chip(desc);
		if (!chip)
			continue;

		/*
		 * First try to remove the active state. If this
		 * fails, try to EOI the interrupt.
		 */
		ret = irq_set_irqchip_state(i, IRQCHIP_STATE_ACTIVE, false);

		if (ret && irqd_irq_inprogress(&desc->irq_data) &&
		    chip->irq_eoi)
			chip->irq_eoi(&desc->irq_data);

		if (chip->irq_mask)
			chip->irq_mask(&desc->irq_data);

		if (chip->irq_disable && !irqd_irq_disabled(&desc->irq_data))
			chip->irq_disable(&desc->irq_data);
	}
}

/**
 * machine_crash_shutdown - shutdown non-crashing cpus and save registers
 */
void machine_crash_shutdown(struct pt_regs *regs)
{
	local_irq_disable();

	/* shutdown non-crashing cpus */
	crash_smp_send_stop();

	/* for crashing cpu */
	crash_save_cpu(regs, smp_processor_id());
	machine_kexec_mask_interrupts();

	pr_info("Starting crashdump kernel...\n");
}

void arch_kexec_protect_crashkres(void)
{
	int i;

	kexec_segment_flush(kexec_crash_image);

	for (i = 0; i < kexec_crash_image->nr_segments; i++)
		set_memory_valid(
			__phys_to_virt(kexec_crash_image->segment[i].mem),
			kexec_crash_image->segment[i].memsz >> PAGE_SHIFT, 0);
}

void arch_kexec_unprotect_crashkres(void)
{
	int i;

	for (i = 0; i < kexec_crash_image->nr_segments; i++)
		set_memory_valid(
			__phys_to_virt(kexec_crash_image->segment[i].mem),
			kexec_crash_image->segment[i].memsz >> PAGE_SHIFT, 1);
}

#ifdef CONFIG_HIBERNATION
/*
 * To preserve the crash dump kernel image, the relevant memory segments
 * should be mapped again around the hibernation.
 */
void crash_prepare_suspend(void)
{
	if (kexec_crash_image)
		arch_kexec_unprotect_crashkres();
}

void crash_post_resume(void)
{
	if (kexec_crash_image)
		arch_kexec_protect_crashkres();
}

/*
 * crash_is_nosave
 *
 * Return true only if a page is part of reserved memory for crash dump kernel,
 * but does not hold any data of loaded kernel image.
 *
 * Note that all the pages in crash dump kernel memory have been initially
 * marked as Reserved in kexec_reserve_crashkres_pages().
 *
 * In hibernation, the pages which are Reserved and yet "nosave" are excluded
 * from the hibernation iamge. crash_is_nosave() does thich check for crash
 * dump kernel and will reduce the total size of hibernation image.
 */

bool crash_is_nosave(unsigned long pfn)
{
	int i;
	phys_addr_t addr;

	if (!crashk_res.end)
		return false;

	/* in reserved memory? */
	addr = __pfn_to_phys(pfn);
	if ((addr < crashk_res.start) || (crashk_res.end < addr))
		return false;

	if (!kexec_crash_image)
		return true;

	/* not part of loaded kernel image? */
	for (i = 0; i < kexec_crash_image->nr_segments; i++)
		if (addr >= kexec_crash_image->segment[i].mem &&
				addr < (kexec_crash_image->segment[i].mem +
					kexec_crash_image->segment[i].memsz))
			return false;

	return true;
}

void crash_free_reserved_phys_range(unsigned long begin, unsigned long end)
{
	unsigned long addr;
	struct page *page;

	for (addr = begin; addr < end; addr += PAGE_SIZE) {
		page = phys_to_page(addr);
		ClearPageReserved(page);
		free_reserved_page(page);
	}
}
#endif /* CONFIG_HIBERNATION */

void arch_crash_save_vmcoreinfo(void)
{
	VMCOREINFO_NUMBER(VA_BITS);
	/* Please note VMCOREINFO_NUMBER() uses "%d", not "%x" */
	vmcoreinfo_append_str("NUMBER(kimage_voffset)=0x%llx\n",
						kimage_voffset);
	vmcoreinfo_append_str("NUMBER(PHYS_OFFSET)=0x%llx\n",
						PHYS_OFFSET);
}
