#include <linux/slab.h>
#include <asm/cacheflush.h>
#include "mmuhack.h"
#include "dumpcode.h"
#include "gphook.h"

LIST_HEAD(hooklist);

void *execmem = NULL;
void *execmem_lastused = NULL;
pmd_t execmem_pmd;

void cacheflush ( void *begin, unsigned long size )
{
    printk("Flushing cache.\n");
    //do_cache_op((unsigned long) begin, (unsigned long)begin + size, 0);
    clean_dcache_area(begin, PAGE_SIZE);
    flush_icache_range((unsigned long) begin, (unsigned long)begin + PAGE_SIZE);
    //cpu_cache.flush_kern_all();
    //__cpuc_flush_icache_all();

//    asm ("MOV r0, #0\nMCR p15, 0, r0, c7, c5, 0;");
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
    
    #if defined(__arm__)
    //OK. We are in ARM. We need to check system is using THUMB or not.
    //TODO: Find neat way instead dividing addr with 4.

    //Ok. Here is hacky way to check function is THUMB or not.
    //MOV R12, R13 occurs every function prologue with ARM.
    //check 0xE1A0C0D0 - MOV R12, R13 in non-thumb.
    //TODO: Is it gcc specific?

    //if(*((unsigned long *)addr) == 0xE1A0C0D0) { //not thumb.
    if((unsigned long)addr % 4 == 0) {
        printk("0x%p is not thumb.\n", addr);
        memcpy(hookcode, HOOKCODE, HOOKCODE_SIZE);
    } else {
        printk("0x%p is thumb.\n", addr);
        memcpy(hookcode, HOOKCODE_THUMB, HOOKCODE_SIZE);
    }

    #endif

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

int enable_hook(void *addr) {
    hook_t *hook;

    list_for_each_entry(hook, &hooklist, list) {
        if(addr == hook -> addr && hook -> active == 0) {
            pmd_t pmd_backup;

            pmd_backup = remove_pmd_flag((unsigned long) addr, PMD_SECT_APX);

            memcpy(addr, hook->n_opcode, hook->opcode_size);

            restore_pmd((unsigned long) addr, pmd_backup);

            #if defined(__arm__)
            cacheflush(addr, hook -> opcode_size);
            #endif

            hook -> active = 1;

            return 0;
        }
    }

    return -1;
}

int disable_hook(void *addr) {
    hook_t *hook;

    list_for_each_entry(hook, &hooklist, list) {
        if(addr == hook -> addr && hook -> active == 1) {
            pmd_t pmd_backup;

            pmd_backup = remove_pmd_flag((unsigned long) addr, PMD_SECT_APX);

            dumpcode((unsigned char *) addr, 16);
            memcpy(addr, hook->o_opcode, hook->opcode_size);

            dumpcode((unsigned char *) addr, 16);
            restore_pmd((unsigned long) addr, pmd_backup);

            #if defined(__arm__)
            cacheflush(addr, hook->opcode_size);
            #endif

            hook -> active = 0;

            return 0;
        }
    }

    return -1;
}
