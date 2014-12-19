#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include "mmuhack.h"

void (*my_flush_tlb_kernel_page)(unsigned long);

void (*get_flush_tlb_kernel_page(void))(unsigned long)
{
	void (*func)(unsigned long) = (void*) kallsyms_lookup_name("flush_tlb_kernel_page");
	printk("flush_tlb_kernel_page found at %p\n", func);
	return func;
}

void init_mmuhack()
{
	my_flush_tlb_kernel_page = get_flush_tlb_kernel_page();
}

pmd_t *get_pmd_addr(unsigned long addr)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->active_mm;
	pgd_t *pgd = pgd_offset(mm, addr);
	pud_t *pud = pud_offset(pgd, addr);
	pmd_t *pmd = pmd_offset(pud, addr);

	printk("Get PMD of 0x%lx: 0x%p\n", addr, pmd);
	
	return pmd;
}

pmd_t remove_pmd_flag(unsigned long addr, unsigned long mask)
{
	pmd_t *pmd = get_pmd_addr(addr);
	pmd_t *pmd_to_flush = pmd;
	pmd_t saved_pmd;

	if (addr & SECTION_SIZE) {
		pmd++;
	}

	saved_pmd = *pmd;

	if ((saved_pmd & PMD_TYPE_MASK) != PMD_TYPE_SECT)
		return saved_pmd;

	if (*pmd & mask)
	{
		*pmd &= ~mask;
	} else {
		printk("Uh... I think this page (0x%08lX - 0x%08lX) s flag 0x%08lX is already removed.\n", addr & PAGE_MASK, (addr & PAGE_MASK) + (~PAGE_MASK), mask);
		return saved_pmd;
	}

	flush_pmd_entry(pmd_to_flush);
	my_flush_tlb_kernel_page(addr & PAGE_MASK);

	printk("Page 0x%08lX - 0x%08lX pmd flag 0x%08lX removed.\n", addr & PAGE_MASK, (addr & PAGE_MASK) + (~PAGE_MASK), mask);
	return saved_pmd;
}

void restore_pmd(unsigned long addr, pmd_t pmd_to_restore)
{
	pmd_t *pmd = get_pmd_addr(addr);

	if (addr & SECTION_SIZE) {
		pmd++;
	}

	printk("Restoring PMD 0x%08lX to 0x%08lX\n", (unsigned long) pmd_to_restore, addr);

	*pmd = pmd_to_restore;

	flush_pmd_entry(pmd);
	my_flush_tlb_kernel_page(addr & PAGE_MASK);

	printk("Page 0x%08lX - 0x%08lX restored.\n", addr & PAGE_MASK, (addr & PAGE_MASK) + (~PAGE_MASK) - 1);
}
