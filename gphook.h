#include <linux/list.h>

/*
 * Opcode examples. (Jump to 0xDEADBEEF)
 *
 * JMP opcode for three major platform. (ARM, MIPS, x86)
 * ARM Full  - LDR PC, [PC]; NOP; DB addr
 *             0x00 0xF0 0x9F 0xE5 0x00 0x00 0x00 0x00 0xEF 0xBE 0xAD 0xDE
 *
 * ARM Thumb - ADR R0, 0x00000008; MOV R15, R0; NOP; DB addr
 *             ADD R0, PC; LDR R0, [R0, #0]; MOV R15, R0; NOP, DB addr
 *             0x01 0xA0 0x00 0x68 0x87 0x46 0x00 0xBF 0xEF 0xBE 0xAD 0xDE
 *
 * MIPS      - TODO: Add MIPS support
 * x86       - TODO: Add Intel x86 support
 */

#if defined(__arm__)

#ifndef CONFIG_THUMB2_KERNEL
#define HOOKCODE "\x00\xF0\x9F\xE5\x00\x00\x00\x00\xEF\xBE\xAD\xDE"
#else
#define HOOKCODE "\x01\xA0\x00\x68\x87\x46\x00\xBF\xEF\xBE\xAD\xDE"
#endif

#define HOOKCODE_SIZE 12
#define HOOKCODE_ADDROFFSET 8

#elif defined(__mips__)
#error "MIPS is not yet supported!"
#elif defined(__x86__)

#error "AMD64 is not yet supported!"
#else
#error "This architecture is not supported!"
#endif

struct hook_s {
    void *addr;
    int addroffset;
    int opcode_size;
    int active;
    int active_chg;
    void *callorig;
    char o_opcode[HOOKCODE_SIZE];
    char n_opcode[HOOKCODE_SIZE];
    struct list_head list;
};

typedef struct hook_s hook_t;

void cacheflush(void *begin, unsigned long size);
int init_hook(void);
void cleanup_hook(void);
hook_t *install_hook(void *addr, void *hookaddr);
int remove_hook(void *addr);
int enable_hook(hook_t *hook);
int disable_hook(hook_t *hook);
