#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/stop_machine.h>
#include <asm/cacheflush.h>
#include <asm/outercache.h>
#include <asm/smp_plat.h>
#include <asm/tlbflush.h>
#include "mmuhack.h"
#include "gphook.h"

LIST_HEAD(hooklist);

void *execmem = NULL;
void *execmem_lastused = NULL;
mmuhack_t execmem_hack;

void cacheflush ( void *begin, unsigned long size )
{
    uintptr_t __volatile__ beginaddr = (uintptr_t)begin;
    uintptr_t __volatile__ endaddr = (uintptr_t)begin + size;
    #if defined(__arm__)
    printk("Flushing 0x%08lX-0x%08lX.\n", beginaddr, endaddr);
    __asm__ __volatile__ (
            "LDR r2, %0\n"
            "LDR r3, %1\n"
            "MRC p15, 0, r0, c0, c0, 1\n" //Read CTR.
            "LSR r0, r0, #16\n"           //Shift 16bit
            "AND r0, r0, #0b1111\n"       //get dcache line size.
            "MOV r1, #4\n"                //word size: 4byte
            "MOV r1, r1, lsl r0\n"        //r1 = r1 >> r0. Now r1 has dcache line size.
            "SUB r0, r1, #1\n"            //r1 - 1 = bitmask of dcache line size.
            "BIC r0, r2, r0\n"            //Calculate dcache to flush \w beginaddr and bitmask
#ifdef CONFIG_SMP
            "DSB\n"                       //Full data sync barrier only in SMP
#endif
            "NOP\n"
            "1:\n"
            //"MCR p15, 0, r0, c7, c11, 1\n"//Clean dcache to PoU.
            "MCR p15, 0, r0, c7, c10, 1\n"//Clean dcache line by MVA to PoC
            //"DSB\n"
            //"MCR p15, 0, r0, c7, c14, 1\n"//Clean and invalidate dcache to PoC.
            "ADD r0, r0, r1\n"            //Add dcache line size.
            "CMP r0, r3\n"                //Check we flushed all.
            "BLO 1b\n"                    //Loop until we flush all.
            "DSB ishst\n"
            "MRC p15, 0, r0, c0, c0, 1\n" //Read CTR.
            "AND r0, r0, #0b1111\n"       //get icache line size
            "MOV r1, #4\n"                //word size: 4byte
            "MOV r1, r1, lsl r0\n"        //r1 = r1 >> r0. Now r1 has icache line size
            "SUB r0, r1, #1\n"            //r1 - 1 = bitmask of icache line size
            "BIC r0, r2, r0\n"            //Calculate icache to flush \w beginaddr and bitmask
            "2:\n"
            "MCR p15, 0, r0, c7, c5, 1\n" //Invalidate icache.
            "ADD r0, r0, r1\n"            //Add icache line size.
            "CMP r0, r3\n"                //Check we flushed all.
            "BLO 2b\n"                    //Loop until we flush all.
            "MOV r0, #0\n"
            //"MCR p15, 0, r0, c7, c1, 0\n" //Invalidate all icache.
#ifdef CONFIG_SMP
            "MCR p15, 0, r0, c7, c1, 6\n" //Invalidate BTB Inner sharable.
#endif
            "MCR P15, 0, r0, c7, c5, 6\n" //Invalidate BTB
            "DSB ishst\n"
            "ISB\n"                       //Instruction barrier.
            : "=m" (beginaddr), "=m" (endaddr));

    printk("Address 0x%08lX-0x%08lX flushed.\n", beginaddr, endaddr);

    //TODO: USE ALT_SMP, ALT_UP. https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git/tree/arch/arm/mm/cache-v7.S
    #else
    printk("Cacheflush not needed.\n");
    #endif
}

int init_hook(void) {
    execmem = kmalloc(PAGE_SIZE, GFP_KERNEL);
    execmem_lastused = execmem;

    init_mmuhack(&execmem_hack, (uintptr_t) execmem);

    if(execmem == NULL) {
        return -1;
    }

    remove_pmd_flag(&execmem_hack, PMD_SECT_XN);

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
    restore_pmd_flag(&execmem_hack);
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
    mmuhack_t hook_hack;
    int i;

    init_mmuhack(&hook_hack, (uintptr_t)hook -> addr);
    remove_pmd_flag(&hook_hack, PMD_SECT_APX);

    if(hook -> active_chg) {
        for (i = 0; i < hook -> opcode_size / 4; i++) {
            *(uint32_t*)(hook -> addr + 4 * i) = *(uint32_t*)(hook -> n_opcode + 4 * i);
        }
        //memcpy(hook -> addr, hook -> n_opcode, hook -> opcode_size);
        hook -> active = 1;
    } else {
        for (i = 0; i < hook -> opcode_size / 4; i++) {
            *(uint32_t*)(hook -> addr + 4 * i) = *(uint32_t*)(hook -> o_opcode + 4 * i);
        }
        //memcpy(hook -> addr, hook -> o_opcode, hook -> opcode_size);
        hook -> active = 0;
    }


    cacheflush(hook -> addr, hook -> opcode_size);

    restore_pmd_flag(&hook_hack);

    return 0;
}

int __change_hook(hook_t *hook, int active_chg) {

    if(hook -> active != active_chg) {
        hook -> active_chg = active_chg;
        if (cache_ops_need_broadcast()) {
            printk("stop_machine is needed.\n");
            stop_machine((int (*)(void*)) __apply_hook, hook, cpu_online_mask);
        } else {
            //TODO: check straddles_word

            //stop_machine((int (*)(void*)) __apply_hook, hook, cpu_online_mask);
            __apply_hook(hook);
        }

        return 0;
    }

    return -1;
}

int enable_hook(hook_t *hook) {
    return __change_hook(hook, 1);
}

int disable_hook(hook_t *hook) {
    return __change_hook(hook, 0);
}
