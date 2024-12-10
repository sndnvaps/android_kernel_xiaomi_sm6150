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

#include <linux/kexec.h>
#include <linux/linkage.h>

#include <asm/assembler.h>
#include <asm/kexec.h>
#include <asm/page.h>
#include <asm/sysreg.h>


#ifdef CONFIG_KEXEC_HARDBOOT
// SM6150 specific
#define MPM2_MPM_PS_HOLD	0xC264000
#endif
.data

/*
 * arm64_relocate_new_kernel - Put a 2nd stage image in place and boot it.
 *
 * The memory that the old kernel occupies may be overwritten when coping the
 * new image to its final location.  To assure that the
 * arm64_relocate_new_kernel routine which does that copy is not overwritten,
 * all code and data needed by arm64_relocate_new_kernel must be between the
 * symbols arm64_relocate_new_kernel and arm64_relocate_new_kernel_end.  The
 * machine_kexec() routine will copy arm64_relocate_new_kernel to the kexec
 * control_code_page, a special page which has been set up to be preserved
 * during the copy operation.
 */
ENTRY(arm64_relocate_new_kernel)

	ldr	x22, =KEXEC_HB_PAGE_ADDR
	ldr	x23, =(0xdeaf0000)
	str	x23, [x22]
	ldr	x24, arm64_kexec_hardboot
	cbz	x24, first_not_hardboot //判断x24寄存器是否为0，若为0，跳转到first_not_hardboot标签处
	str	x23, [x22, #56]
first_not_hardboot:
	/* Setup the list loop variables. */
	//mov	x17, x1				/* x17 = kimage_start */
	//mov	x16, x0				/* x16 = kimage_head */
	mov x17, x1					/* x17 = kimage_start */
	ldr x16, arm64_kexec_kimage_head	/* x16 = list entry */
	mov x16, x0					/* x16 = kimage_head */
	raw_dcache_line_size x15, x0		/* x15 = dcache line size */
	mov	x14, xzr			/* x14 = entry ptr */
	mov	x13, xzr			/* x13 = copy dest */

	/* Clear the sctlr_el2 flags. */
	mrs	x0, CurrentEL
	cmp	x0, #CurrentEL_EL2
	b.ne	1f
	mrs	x0, sctlr_el2
	ldr	x1, =SCTLR_ELx_FLAGS
	bic	x0, x0, x1
	pre_disable_mmu_workaround
	msr	sctlr_el2, x0
	isb
1:

	/* Check if the new image needs relocation. */
	tbnz	x16, IND_DONE_BIT, .Ldone

.Lloop:
	and	x12, x16, PAGE_MASK		/* x12 = addr */

	/* Test the entry flags. */
.Ltest_source:
	tbz	x16, IND_SOURCE_BIT, .Ltest_indirection

	/* Invalidate dest page to PoC. */
	mov     x0, x13
	add     x20, x0, #PAGE_SIZE
	sub     x1, x15, #1
	bic     x0, x0, x1
2:	dc      ivac, x0
	add     x0, x0, x15
	cmp     x0, x20
	b.lo    2b
	dsb     sy

	mov x20, x13
	mov x21, x12
	copy_page x20, x21, x0, x1, x2, x3, x4, x5, x6, x7

	/* dest += PAGE_SIZE */
	add	x13, x13, PAGE_SIZE
	b	.Lnext

.Ltest_indirection:
	tbz	x16, IND_INDIRECTION_BIT, .Ltest_destination

	/* ptr = addr */
	mov	x14, x12
	b	.Lnext

.Ltest_destination:
	tbz	x16, IND_DESTINATION_BIT, .Lnext

	/* dest = addr */
	mov	x13, x12

.Lnext:
	/* entry = *ptr++ */
	ldr	x16, [x14], #8

	ldr	x24, arm64_kexec_hardboot  
	cbz	x24, second_not_hardboot	//判断x24寄存器是否为0，若为0，跳转到second_not_hardboot标签处
	ldr	x22, =KEXEC_HB_PAGE_ADDR	//

	ldr	x23, [x22, #56]

	add	x23, x23, #1
	str	x23, [x22, #56]
second_not_hardboot:

	/* while (!(entry & DONE)) */
	tbz	x16, IND_DONE_BIT, .Lloop

.Ldone:
	/* wait for writes from copy_page to finish */
	dsb	nsh
	ic	iallu
	dsb	nsh
	isb

#ifdef CONFIG_KEXEC_HARDBOOT
	ldr	x0, arm64_kexec_hardboot  // 将arm64_kexec_hardboot的值传给x0寄存器，（0，1）
	cbnz	x0, hardboot			//如果寄存器x0的值不为0，跳转到hardboot 标签处，执行指令
#endif
	ldr	x22, =KEXEC_HB_PAGE_ADDR
	ldr	x23, =(0xfeedf00d)
	str	x23, [x22]

	/* Start new image. */
	ldr x17, arm64_kexec_kimage_start
	ldr	x0, arm64_kexec_dtb_addr

	str	x17, [x22, #8]
	str	x0, [x22, #16]
	str	xzr, [x22, #24]

	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr
	br	x17

#ifdef CONFIG_KEXEC_HARDBOOT
hardboot:
	/* Stash boot arguments in hardboot page:
	 * 0: KEXEC_HB_PAGE_MAGIC
	 * 8: kexec_kimage_start
	 */
	ldr	x0, =KEXEC_HB_PAGE_ADDR
	ldr	x1, =KEXEC_HB_PAGE_MAGIC
	str	x1, [x0]
	/* Processor specific reboot code. */
	/* SM6150 version. */
	ldr	x0, =MPM2_MPM_PS_HOLD
	str	xzr, [x0]
loop:	b	loop
#endif
ENDPROC(arm64_relocate_new_kernel)

.ltorg

.align 3	/* To keep the 64-bit values below naturally aligned. */

/* The machine_kexec routines set these variables. */

/*
 * arm64_kexec_kimage_start - Copy of image->start, the entry point of the new
 * image.
 */
.globl arm64_kexec_kimage_start
arm64_kexec_kimage_start:
	.quad	0x0
/*
 * arm64_kexec_kimage_head - Copy of image->head, the list of kimage entries.
 */
.globl arm64_kexec_kimage_head
arm64_kexec_kimage_head:
	.quad	0x0

/*
 * arm64_kexec_hardboot - set to true if booting in hardboot mode
 */
.globl arm64_kexec_hardboot
arm64_kexec_hardboot:
	.quad	0x0

/*
 * arm64_kexec_dtb_addr - Physical address of a device tree.
 */
.globl arm64_kexec_dtb_addr
arm64_kexec_dtb_addr:
	.quad	0x0

.Lrelocate_new_kernel_end:

/*
 * arm64_relocate_new_kernel_size - Number of bytes to copy to the
 * control_code_page.
 */
.globl arm64_relocate_new_kernel_size
arm64_relocate_new_kernel_size:
	.quad	.Lrelocate_new_kernel_end - arm64_relocate_new_kernel

.org	KEXEC_CONTROL_PAGE_SIZE
