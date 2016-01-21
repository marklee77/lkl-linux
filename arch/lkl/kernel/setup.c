#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/reboot.h>
#include <linux/fs.h>
#include <linux/start_kernel.h>
#include <linux/syscalls.h>
#include <asm/host_ops.h>
#include <asm/irq.h>
#include <asm/unistd.h>
#include <asm/syscalls.h>

#include "rump.h"

struct lkl_host_operations *lkl_ops;
static char cmd_line[COMMAND_LINE_SIZE];
static void *idle_sem;
static void *init_sem;
static void *halt_sem;
static bool halt;
void (*pm_power_off)(void) = NULL;
static unsigned long mem_size;

extern char lkl_virtio_devs[];

long lkl_panic_blink(int state)
{
	rumpuser_exit(RUMPUSER_PANIC);
	return 0;
}

void __init setup_arch(char **cl)
{
	*cl = cmd_line;
	panic_blink = lkl_panic_blink;
	bootmem_init(mem_size);
}

int run_init_process(const char *init_filename)
{
	rump_sem_up(init_sem);

	run_syscalls();

	kernel_halt();

	/* We want to kill init without panic()ing */
	init_pid_ns.child_reaper = 0;
	do_exit(0);

	return 0;
}

static void __init lkl_run_kernel(void *arg)
{
	start_kernel();
}

int __init lkl_start_kernel(struct lkl_host_operations *ops,
			    unsigned long _mem_size,
			    const char *fmt, ...)
{
	va_list ap;
	int ret;
	void *thr;
	char *virtio_devices;

	mem_size = _mem_size;

	va_start(ap, fmt);
	ret = vsnprintf(boot_command_line, COMMAND_LINE_SIZE, fmt, ap);
	va_end(ap);

	virtio_devices = lkl_virtio_devs;
	if (virtio_devices)
		strncpy(boot_command_line + ret, virtio_devices,
			COMMAND_LINE_SIZE - ret);

	memcpy(cmd_line, boot_command_line, COMMAND_LINE_SIZE);

	ret = threads_init();
	if (ret)
		return ret;

	init_sem = rump_sem_alloc(0);
	if (!init_sem)
		return -ENOMEM;

	idle_sem = rump_sem_alloc(0);
	if (!idle_sem) {
		ret = -ENOMEM;
		goto out_free_init_sem;
	}

	ret = rumpuser_thread_create((void * (*)(void *))lkl_run_kernel, NULL,
				     "lkl_init", 0, 1, -1, &thr);
	if (ret) {
		ret = -ENOMEM;
		goto out_free_idle_sem;
	}

	rump_sem_down(init_sem);

	return 0;

out_free_idle_sem:
	rump_sem_free(idle_sem);

out_free_init_sem:
	rump_sem_free(init_sem);

	return ret;
}

void machine_halt(void)
{
	halt = true;
}

void machine_power_off(void)
{
	machine_halt();
}

void machine_restart(char *unused)
{
	machine_halt();
}

long lkl_sys_halt(void)
{
	long err;
	long params[6] = { 0, };

	halt_sem = rump_sem_alloc(0);
	if (!halt_sem)
		return -ENOMEM;

	rump_exit();
	err = lkl_syscall(__NR_reboot, params);
	if (err < 0) {
		rump_sem_free(halt_sem);
		return err;
	}

	rump_sem_down(halt_sem);

	rump_sem_free(halt_sem);
	rump_sem_free(idle_sem);
	rump_sem_free(init_sem);

	return 0;
}

void arch_cpu_idle(void)
{
	if (halt) {
		threads_cleanup();
		free_IRQ();
		free_mem();
		rump_sem_up(halt_sem);
		rumpuser_thread_exit();
	}

	rump_sem_down(idle_sem);

	local_irq_enable();
}

void wakeup_cpu(void)
{
	rump_sem_up(idle_sem);
}

/* skip mounting the "real" rootfs. ramfs is good enough. */
static int __init fs_setup(void)
{
	int fd;

	fd = sys_open("/init", O_CREAT, 0600);
	WARN_ON(fd < 0);
	sys_close(fd);

	return 0;
}
late_initcall(fs_setup);
