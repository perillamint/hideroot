#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <asm/cacheflush.h>
#include <asm/outercache.h>
#include <asm/smp_plat.h>
#include "mmuhack.h"
#include "gphook.h"

LIST_HEAD(hooklist);

void *execmem = NULL;
void *execmem_lastused = NULL;
pmd_t execmem_pmd;

static inline void cacheflush ( void *begin, unsigned long size )
{
    #if defined(__arm__)
    flush_icache_range((uintptr_t) begin, (uintptr_t)begin + size);
    #else
    printk("Cacheflush not needed.\n");
    #endif
}

int init_hook(void) {
    execmem = kmalloc(PAGE_SIZE, GFP_KERNEL);
    execmem_lastused = execmem;

    if(execmem == NULL) {
        return -1;
    }

    execmem_pmd = remove_pmd_flag((unsigned long)execmem, PMD_SECT_XN);

    return 0;
}

void cleanup_hook(void) {
    hook_t *hook;
    hook_t *tmp;

    list_for_each_entry_safe(hook, tmp, &hooklist, list) {
        printk("Removing 0x%p\n", hook);
        remove_hook(hook -> addr);
    }

    printk("All done! freeing execmem.\n");
    restore_pmd((unsigned long)execmem, execmem_pmd);
    kfree(execmem);
}

//Some dark magic to call original function in hooked function.
void register_origcall(hook_t *hook) {
    //TODO: add boundary check.
    unsigned long address = (unsigned long)hook -> addr + hook -> opcode_size;

    hook -> callorig = execmem_lastused;

    memcpy(execmem_lastused, hook -> o_opcode, hook -> opcode_size);
    execmem_lastused += (hook -> opcode_size);
    memcpy(execmem_lastused, hook -> n_opcode, hook -> opcode_size);
    memcpy(execmem_lastused + hook -> addroffset, &address, 4);
    execmem_lastused += (hook -> opcode_size);
}

/*
 * Builds JMP opcode to *addr for current platform.
 * returnvalue -> opcode must freed after using value.
 */

hook_t *install_hook(void *addr, void *hookaddr) {
    char hookcode[HOOKCODE_SIZE];
    hook_t *hook = 0x00000000;

    memcpy(hookcode, HOOKCODE, HOOKCODE_SIZE);

    //Assuming 32-bit environment...
    memcpy(hookcode + HOOKCODE_ADDROFFSET, &hookaddr, 4);

    hook = kmalloc(sizeof(*hook), GFP_KERNEL);

    if(!hook) return 0;

    /**
     * TODO: Check more cases..
     * If function prologue uses LDR, using o_opcode in different location
     * will lead to unexpected behavior. (and kernel panic!)
    **/

    memcpy(hook -> o_opcode, addr, HOOKCODE_SIZE);
    memcpy(hook -> n_opcode, hookcode, HOOKCODE_SIZE);

    hook -> addr = addr;
    hook -> addroffset = HOOKCODE_ADDROFFSET;
    hook -> opcode_size = HOOKCODE_SIZE;
    hook -> active = 0;
    hook -> active_chg = 0;
    register_origcall(hook);

    list_add(&(hook->list), &hooklist);

    printk("Hook 0x%p installed in 0x%p\n", hookaddr, addr);

    return hook;
}

int remove_hook(void *addr) {
    hook_t *hook;

    list_for_each_entry(hook, &hooklist, list) {
        if(addr == hook -> addr) {
            if(hook -> active == 1) {
                disable_hook(addr);
            }

            list_del(&(hook->list));
            kfree(hook);

            return 0;
        }
    }
    return -1;
}

int __apply_hook(hook_t *hook) {
    pmd_t pmd_backup;

    pmd_backup = remove_pmd_flag((uintptr_t)hook -> addr, PMD_SECT_APX);

    if(hook -> active_chg) {
        memcpy(hook -> addr, hook -> n_opcode, hook -> opcode_size);
        hook -> active = 1;
    } else {
        memcpy(hook -> addr, hook -> o_opcode, hook -> opcode_size);
        hook -> active = 0;
    }

    restore_pmd((uintptr_t)hook -> addr, pmd_backup);

    cacheflush(hook -> addr, hook -> opcode_size);

    return 0;
}

int __change_hook(void *addr, int active_chg) {
    hook_t *hook;

    list_for_each_entry(hook, &hooklist, list) {
        if(addr == hook -> addr && hook -> active != active_chg) {
            hook -> active_chg = active_chg;
            if (cache_ops_need_broadcast()) {
                printk("stop_machine is needed.\n");
                stop_machine((int (*)(void*)) __apply_hook, hook, cpu_online_mask);
            } else {
                //TODO: check straddles_word

                __apply_hook(hook);
            }

            return 0;
        }
    }

    return -1;
}

int enable_hook(void *addr) {
    return __change_hook(addr, 1);
}

int disable_hook(void *addr) {
    return __change_hook(addr, 0);
}
