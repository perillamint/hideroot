#include <asm/pgtable.h>

void init_mmuhack(void);
pmd_t remove_pmd_flag(unsigned long addr, unsigned long flag);
void restore_pmd(unsigned long addr, pmd_t pmd_to_restore);
