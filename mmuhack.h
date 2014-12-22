#include <asm/pgtable.h>

struct mmuhack_s {
    uintptr_t addr;
    pmd_t *pmd;
    pmd_t origpmd;
};

typedef struct mmuhack_s mmuhack_t;

int init_mmuhack(mmuhack_t *mmuhack, uintptr_t addr);
void remove_pmd_flag(mmuhack_t *mmuhack, unsigned long flag);
void restore_pmd_flag(mmuhack_t *mmuhack);
