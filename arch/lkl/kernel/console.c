#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/console.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/kdev_t.h>

#include "rump.h"

static void console_write(struct console *con, const char *str, unsigned len)
{
	while (len-- > 0) {
		rumpuser_putchar(*str);
		str++;
	}
}

static ssize_t file_write(struct file *fp, const char __user *s,
			  size_t n, loff_t *off)
{
	console_write(NULL, s, n);
	return n;
}

#ifdef CONFIG_LKL_EARLY_CONSOLE
static struct console lkl_boot_console = {
	.name	= "lkl_boot_console",
	.write	= console_write,
	.flags	= CON_PRINTBUFFER | CON_BOOT,
	.index	= -1,
};

int __init lkl_boot_console_init(void)
{
	register_console(&lkl_boot_console);
	return 0;
}
early_initcall(lkl_boot_console_init);
#endif

/* only support stdout */
static struct file_operations std_stream_dev = {
	.write =	file_write,
};

static void lkl_std_stream_init(void)
{
	struct file *fp;
	int fd, err;

	err = sys_mkdir("/dev", 0755);
	if (err < 0) {
		pr_warn("can't create /dev");
		return;
	}

	fd = sys_open("/dev/console", O_CREAT | O_RDWR | O_NDELAY, 0);
	fp = fget(fd);
	fp->f_op = &std_stream_dev;

	if ((sys_dup3(0, 1, 0) == -1) ||
	    (sys_dup3(0, 2, 0) == -1))
		panic("failed to dup fd 0/1/2");
}

static struct console lkl_console = {
	.name	= "lkl_console",
	.write	= console_write,
	.flags	= CON_PRINTBUFFER,
	.index	= -1,
};


int __init lkl_console_init(void)
{
	register_console(&lkl_console);
	lkl_std_stream_init();
	return 0;
}
core_initcall(lkl_console_init);

