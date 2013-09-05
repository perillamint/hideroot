#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include "dumpcode.h"
#include "util.h"

unsigned long **sys_call_table;

int hide_uid[100]; 
int hide_uid_count;
module_param_array(hide_uid, int, &hide_uid_count, 0);

asmlinkage int my_do_execve(const char __user *filename,
			  const char __user *const __user *argv,
			  const char __user *const __user *envp, struct pt_regs *regs);

static struct jprobe my_jprobe = {
        .entry = (kprobe_opcode_t *) my_do_execve
};

static unsigned long **find_sys_call_table(void)
{
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		if (sct[__NR_close] == (unsigned long *) sys_close) 
			return sct;

		offset += sizeof(void *);
	}

	return NULL;
}

long (*orig_sys_getdents64) (unsigned int fd,
                                struct linux_dirent64 __user *dirent,
                                unsigned int count);

asmlinkage long my_sys_getdents64(unsigned int fd,
                                struct linux_dirent64 __user *dirent,
                                unsigned int count)
{
	int i;
	int fake = 0;
	int offset, copyret;
	struct linux_dirent64 *td1, *td2, *cur, *prev;
	unsigned long ret, tmp;
	char *ptr;
	
	ret = orig_sys_getdents64(fd, dirent, count);

	for(i=0; i<hide_uid_count; i++)
	{
		if(hide_uid[i] == current_uid())
			fake = 1;
	}

	if(fake == 0)
		return ret;

	if(ret <= 0)
		return ret;
	
	if((td2 = kmalloc(ret, GFP_KERNEL)) == NULL)
		goto out;

	copyret = copy_from_user(td2, dirent, ret);

	td1 = td2;
	ptr = (char *)td2;
	tmp = ret;
	prev = NULL;

	while(ptr < (char *)td1 + tmp)
 	{
		cur = (struct linux_dirent64 *) ptr;
		offset = cur->d_reclen;

		if(strstr(cur->d_name, "su") != NULL) {
			if(!prev) {
				ret -= offset;
				td2 = (struct linux_dirent64 *) ((char *)td1 + offset);
			} else {
				prev->d_reclen += offset;
				memset(cur, 0, offset);
			}
		} else {
			prev = cur;
		}
		ptr += offset;
	}

	copyret = copy_to_user((void *)dirent, (void *)td2, ret);
	kfree(td1);

out:
	return ret;
}

long (*orig_sys_access) (const char __user *filename, int mode);
asmlinkage long my_sys_access(const char __user *filename, int mode)
{
	int i, fake = 0;
	long ret;

	ret = orig_sys_access(filename, mode);

        for(i=0; i<hide_uid_count; i++)
        {
                if(hide_uid[i] == current_uid())
                        fake = 1;
        }

	if(fake == 0)
		return ret;
	else
	{
		if(strstr(filename, "su"))
			return -1;
		else
			return ret;
	}
}
/*
asmlinkage long (*orig_do_execve) (const char __user *filenamei,
                          const char __user *const __user *argv,
                          const char __user *const __user *envp, struct pt_regs *regs);
asmlinkage long (*orig_sys_execve) (const char __user *filenamei,
                          const char __user *const __user *argv,
                          const char __user *const __user *envp, struct pt_regs *regs);

*/

asmlinkage int my_do_execve(const char __user *filename,
			  const char __user *const __user *argv,
			  const char __user *const __user *envp, struct pt_regs *regs)
{
	char meaningless[] = "/system/thisfilecannotexist";

	printk("do_execve for %s from %s\n", filename, current->comm);
	if(strstr(filename, "bin/su"))
		filename = meaningless;

	jprobe_return();
	return 0;
}

/*{
	int error;
	char * filename;

	filename = getname(filenamei);
	error = PTR_ERR(filename);
	if (IS_ERR(filename))
		goto out;

	printk("Running orig_do_execve... 0x%p\n", orig_do_execve);
	error = orig_do_execve(filename, argv, envp, regs);
	putname(filename);
out:
	return error;
}*/
/*
{
        int i, fake = 0;
        long ret;

	printk("filenamei = %p, argv = %p, envp = %p, orig_do_execve = %p\n", filenamei, argv, envp, orig_do_execve);

	hijack_pause(orig_do_execve);
        ret = orig_do_execve(filenamei, argv, envp);
	hijack_resume(orig_do_execve);

	printk("filenamei is %s\n", filenamei);

	return ret;

        for(i=0; i<hide_uid_count; i++)
        {
                printk("checking uid=%d\n", hide_uid[i]);
                if(hide_uid[i] == current_uid())
                        fake = 1;
        }

	if(fake == 0)
		return ret;
	else if(ret != -1)
	{
		if(strstr(filenamei, "bin/su"))
			return -1;
		else
			return ret;
	}

	return ret;
}*/

static int init_hideroot(void)
{
	int ret;

	printk("Hooking...\n");
	sys_call_table = find_sys_call_table();
	printk("%p\n", sys_call_table);
	
	//Hook sys_getdents64
	orig_sys_getdents64 = (void*) sys_call_table[__NR_getdents64];
	sys_call_table[__NR_getdents64] = (unsigned long*) my_sys_getdents64;

	//Hook sys_access
	orig_sys_access = (void*) sys_call_table[__NR_access];
	sys_call_table[__NR_access] = (unsigned long*) my_sys_access;

	//Hook sys_execve - It does not work this way.
	//orig_sys_execve = (void*) sys_call_table[__NR_execve];
	//sys_call_table[__NR_execve] = (unsigned long*) my_sys_execve;
	
	//orig_do_execve = (void*)kallsyms_lookup_name("do_execve");
	//hijack_start (orig_do_execve, &my_do_execve);
	//
	my_jprobe.kp.addr = 
                (kprobe_opcode_t *) kallsyms_lookup_name("do_execve");
        if (!my_jprobe.kp.addr) {
                printk("Couldn't find %s to plant jprobe\n", "do_execve");
                return -1;
        }

	if ((ret = register_jprobe(&my_jprobe)) <0) {
                printk("register_jprobe failed, returned %d\n", ret);
                return -1;
        }
        printk("Planted jprobe at %p, handler addr %p\n",
               my_jprobe.kp.addr, my_jprobe.entry);

	return 0;
}

static void cleanup_hideroot(void)
{
	printk("Quitting hider\n");
	sys_call_table[__NR_getdents64] = (unsigned long*) orig_sys_getdents64;
	sys_call_table[__NR_access] = (unsigned long*) orig_sys_access;
	//hijack_stop (orig_do_execve);
	//sys_call_table[__NR_execve] = (unsigned long*) orig_sys_execve;
	unregister_jprobe(&my_jprobe);
}

module_init(init_hideroot);
module_exit(cleanup_hideroot);

MODULE_LICENSE("GPL");
