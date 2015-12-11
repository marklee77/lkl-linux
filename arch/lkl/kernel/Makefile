extra-y := vmlinux.lds

obj-y = setup.o threads.o irq.o time.o syscalls.o misc.o mem.o console.o \
	rump.o rump-host.o rump-sysproxy.o
#lib-y = rump_syscalls.o

SYSCALL_HDR = $(srctree)/include/linux/syscalls.h
SYSCALL_SH = $(srctree)/arch/lkl/scripts/syscall_wrapper.sh
RUMP_GEN_HDR = $(srctree)/arch/lkl/include/linux/rump_syscalls.h
quiet_cmd_syscall = CALL    $@
      cmd_syscall = $(CONFIG_SHELL) ${SYSCALL_SH} ${SYSCALL_HDR} $@ ${RUMP_GEN_HDR}

arch/lkl/kernel/rump_syscalls.c: ${SYSCALL_SH}
	$(call if_changed,syscall)


CFLAGS_rump_syscalls.o += -DRUMP_KERNEL_IS_LIBC
CFLAGS_rump_syscalls.o += -Iinclude/generated/

.NOTPARALLEL : arch/lkl/kernel/rump_syscalls.c ${RUMP_GEN_HDR}
