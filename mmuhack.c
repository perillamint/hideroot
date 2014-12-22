#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include "mmuhack.h"

void (*my_flush_tlb_kernel_page)(unsigned long) = NULL;
void (*my_update_mmu_cache)(struct vm_area_struct *vma, unsigned long) = NULL;

int get_func(void)
{
	my_flush_tlb_kernel_page = (void*) kallsyms_lookup_name("flush_tlb_kernel_page");
	my_update_mmu_cache = (void*) kallsyms_lookup_name("update_mmu_cache");
	printk("flush_tlb_kernel_page found at %p\n", my_flush_tlb_kernel_page);
	printk("update_mmu_cache found at %p\n", my_update_mmu_cache);

    if( my_update_mmu_cache == NULL || my_flush_tlb_kernel_page == NULL )
        return -1;

    return 0;
}

int init_mmuhack(mmuhack_t *mmuhack, uintptr_t addr)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->active_mm;

    pgd_t *pgd = NULL;
    pud_t *pud = NULL;
    pmd_t *pmd = NULL;

    if(my_flush_tlb_kernel_page == NULL) {
        if(get_func() == -1) {
            printk("WARN: some function is not exist.");
            //return -1;
        }
    }

    //my_update_mmu_cache(mm -> vm_area_struct, addr, 
	//my_flush_tlb_kernel_page(addr & PAGE_MASK);
    printk("Getting pgd\n");
	pgd = pgd_offset(mm, addr);
    printk("Getting pud\n");
	pud = pud_offset(pgd, addr);
    printk("Getting pmd\n");
	pmd = pmd_offset(pud, addr);

	printk("Get PMD of 0x%lx: 0x%p\n", addr, pmd);
	
	mmuhack -> pmd = pmd;
    mmuhack -> addr = addr;

    return 0;
}

void remove_pmd_flag(mmuhack_t *mmuhack, unsigned long mask)
{
    pmd_t *pmd = mmuhack -> pmd;
	pmd_t *pmd_to_flush = mmuhack -> pmd;

	if (mmuhack -> addr & SECTION_SIZE) {
	    pmd++;
	}

	mmuhack -> origpmd = *pmd;

	if ((mmuhack -> origpmd & PMD_TYPE_MASK) != PMD_TYPE_SECT)
		return ;

	if (*pmd & mask)
	{
		*pmd &= ~mask;
	} else {
		printk("Uh... I think this page (0x%08lX - 0x%08lX) s flag 0x%08lX is already removed.\n", mmuhack -> addr & PAGE_MASK, (mmuhack -> addr & PAGE_MASK) + (~PAGE_MASK), mask);
		return ;
	}

	flush_pmd_entry(pmd_to_flush);
	my_flush_tlb_kernel_page(mmuhack -> addr & PAGE_MASK);

	printk("Page 0x%08lX - 0x%08lX pmd flag 0x%08lX removed.\n", mmuhack -> addr & PAGE_MASK, (mmuhack -> addr & PAGE_MASK) + (~PAGE_MASK), mask);
}

void restore_pmd_flag(mmuhack_t *mmuhack)
{
    pmd_t *pmd = mmuhack -> pmd;
	if (mmuhack -> addr & SECTION_SIZE) {
		pmd++;
	}

	printk("Restoring PMD 0x%08lX to 0x%08lX\n", (unsigned long) mmuhack -> origpmd, mmuhack -> addr);

	*pmd = mmuhack -> origpmd;

	flush_pmd_entry(pmd);
	my_flush_tlb_kernel_page(mmuhack -> addr & PAGE_MASK);

	printk("Page 0x%08lX - 0x%08lX restored.\n", mmuhack -> addr & PAGE_MASK, (mmuhack -> addr & PAGE_MASK) + (~PAGE_MASK));
}
