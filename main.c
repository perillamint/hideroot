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

#ifdef CONFIG_ARCH_MSM
#include <asm/mmu_writeable.h> //Qualcomm specific code.
#endif

unsigned long **sys_call_table;
unsigned long flags;

int hide_uid[100];
int hide_uid_count=0;
module_param_array_named(hide_uid, hide_uid, int, &hide_uid_count, 0644);

char *hide_file[100] = {"bin/su", };
int hide_file_cnt=1;
module_param_array_named(hide_file, hide_file, charp, &hide_file_cnt, 0644);

int check_hide_uid(void)
{
	int i;
	for (i = 0; i < hide_uid_count; i++)
	{
		if (hide_uid[i] == current_uid())
			return 1;
	}
	return 0;
}

int check_hide_file(const char *filename)
{
	int i;
	for (i=0; i < hide_file_cnt; i++)
	{
		if (strstr(filename, hide_file[i]))
		{
			return 1;
		}
	}

	return 0;
}

asmlinkage int my_do_execve(char __user * filename,
			    const char __user * const __user * argv,
			    const char __user * const __user * envp, struct pt_regs *regs);

static struct jprobe my_jprobe = {
	.entry = (kprobe_opcode_t *) my_do_execve
};

static unsigned long **find_sys_call_table(void)
{
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX)
	{
		sct = (unsigned long **)offset;

		if (sct[__NR_close] == (unsigned long *)sys_close)
			return sct;

		offset += sizeof(void *);
	}

	return NULL;
}

long (*orig_sys_getdents64) (unsigned int fd,
			     struct linux_dirent64 __user * dirent, unsigned int count);

asmlinkage long my_sys_getdents64(unsigned int fd,
				  struct linux_dirent64 __user * dirent, unsigned int count)
{
	int fake = 0;
	int offset, copyret;
	struct linux_dirent64 *td1, *td2, *cur, *prev;
	unsigned long ret, tmp;
	char *ptr;

	ret = orig_sys_getdents64(fd, dirent, count);

	fake = check_hide_uid();

	if (fake == 0)
		return ret;

	if (ret <= 0)
		return ret;

	if ((td2 = kmalloc(ret, GFP_KERNEL)) == NULL)
		goto out;

	copyret = copy_from_user(td2, dirent, ret);

	td1 = td2;
	ptr = (char *)td2;
	tmp = ret;
	prev = NULL;

	while (ptr < (char *)td1 + tmp)
	{
		cur = (struct linux_dirent64 *)ptr;
		offset = cur->d_reclen;

		if (check_hide_file(cur->d_name))
		{
			if (!prev)
			{
				ret -= offset;
				td2 = (struct linux_dirent64 *)((char *)td1 + offset);
			}
			else
			{
				prev->d_reclen += offset;
				memset(cur, 0, offset);
			}
		}
		else
			prev = cur;

		ptr += offset;
	}

	copyret = copy_to_user((void *)dirent, (void *)td2, ret);
	kfree(td1);

      out:
	return ret;
}

long (*orig_sys_access) (const char __user * filename, int mode);
asmlinkage long my_sys_access(const char __user * filename, int mode)
{
	int fake = 0;
	long ret;

	ret = orig_sys_access(filename, mode);

	fake = check_hide_uid();

	if (fake == 0)
		return ret;
	else
	{
		if (check_hide_file(filename))
			return -1;
		else
			return ret;
	}
}

asmlinkage int my_do_execve(char __user * filename,
			    const char __user * const __user * argv,
			    const char __user * const __user * envp, struct pt_regs *regs)
{
	int fake = check_hide_uid();

	if (fake == 0)
		jprobe_return();

	if (check_hide_file(filename))
		filename[0] = 0;

	jprobe_return();
	return 0;
}

long (*orig_sys_stat64) (const char __user * filename, struct stat64 __user * statbuf);
asmlinkage long my_sys_stat64(const char __user * filename, struct stat64 __user * statbuf)
{
	int fake = check_hide_uid();
	long res = orig_sys_stat64(filename, statbuf);

	if (fake == 0)
		return res;

	if (check_hide_file(filename))
		return -1;

	return res;
}

asmlinkage long (*orig_sys_open) (const char __user * filename, int flags, umode_t mode);
asmlinkage long my_sys_open(const char __user * filename, int flags, umode_t mode)
{
	int fake = check_hide_uid();
	long res = orig_sys_open(filename, flags, mode);

	if (fake == 0)
		return res;

	if (check_hide_file(filename))
	{
		sys_close(res);
		return -1;
	}

	return res;
}

static int init_hideroot(void)
{
	int ret;

	printk("Hooking...\n");
	sys_call_table = find_sys_call_table();
	printk("%p\n", sys_call_table);

	printk("Backing up original address...\n");
	orig_sys_getdents64 = (void *)sys_call_table[__NR_getdents64];
	orig_sys_access = (void *)sys_call_table[__NR_access];
	orig_sys_stat64 = (void *)sys_call_table[__NR_stat64];
	orig_sys_open = (void *)sys_call_table[__NR_open];

#ifdef CONFIG_ARCH_MSM
	printk("Qualcomm detected. using mem_text_write_kernel_world to modify sys_call_table.\n");
	mem_text_write_kernel_word((unsigned long *)&sys_call_table[__NR_getdents64], (unsigned long)my_sys_getdents64);
	mem_text_write_kernel_word((unsigned long *)&sys_call_table[__NR_access], (unsigned long)my_sys_access);
	mem_text_write_kernel_word((unsigned long *)&sys_call_table[__NR_stat64], (unsigned long)my_sys_stat64);
	mem_text_write_kernel_word((unsigned long *)&sys_call_table[__NR_open], (unsigned long)my_sys_open);
#else
	sys_call_table[__NR_getdents64] = (unsigned long *)my_sys_getdents64;
	sys_call_table[__NR_access] = (unsigned long *)my_sys_access;
	sys_call_table[__NR_stat64] = (unsigned long *)my_sys_stat64;
	sys_call_table[__NR_open] = (unsigned long *)my_sys_open;
#endif

	// Hook do_execve using jprobe
	my_jprobe.kp.addr = (kprobe_opcode_t *) kallsyms_lookup_name("do_execve");
	if (!my_jprobe.kp.addr)
	{
		printk("Couldn't find %s to plant jprobe\n", "do_execve");
		return -1;
	}

	if ((ret = register_jprobe(&my_jprobe)) < 0)
	{
		printk("register_jprobe failed, returned %d\n", ret);
		return -1;
	}
	printk("Planted jprobe at %p, handler addr %p\n", my_jprobe.kp.addr, my_jprobe.entry);
	return 0;
}

static void cleanup_hideroot(void)
{
	printk("Unhooking...\n");

#ifdef CONFIG_ARCH_MSM
	printk("Qualcomm detected. using mem_text_write_kernel_world to modify sys_call_table.\n");
	mem_text_write_kernel_word((unsigned long *)&sys_call_table[__NR_getdents64], (unsigned long)orig_sys_getdents64);
	mem_text_write_kernel_word((unsigned long *)&sys_call_table[__NR_access], (unsigned long)orig_sys_access);
	mem_text_write_kernel_word((unsigned long *)&sys_call_table[__NR_stat64], (unsigned long)orig_sys_stat64);
	mem_text_write_kernel_word((unsigned long *)&sys_call_table[__NR_open], (unsigned long)orig_sys_open);
#else
	sys_call_table[__NR_getdents64] = (unsigned long *)orig_sys_getdents64;
	sys_call_table[__NR_access] = (unsigned long *)orig_sys_access;
	sys_call_table[__NR_stat64] = (unsigned long *)orig_sys_stat64;
	sys_call_table[__NR_open] = (unsigned long *)orig_sys_open;
#endif
	unregister_jprobe(&my_jprobe);
}

module_init(init_hideroot);
module_exit(cleanup_hideroot);

MODULE_LICENSE("GPL");
