extra-y := vmlinux.lds

obj-y = setup.o threads.o irq.o time.o syscalls.o misc.o mem.o console.o \
	rump.o rump-host.o rump-sysproxy.o
lib-y = rump_syscalls.o

UNISTD_HDR = $(srctree)/arch/lkl/include/uapi/asm/unistd.h
SYSCALL_SH = $(srctree)/arch/lkl/scripts/syscall_wrapper.sh
RUMP_GEN_HDR = $(srctree)/arch/lkl/include/linux/rump_syscalls.h
quiet_cmd_syscall = CALL    $@
      cmd_syscall = $(CONFIG_SHELL) ${SYSCALL_SH} ${UNISTD_HDR} $@ ${RUMP_GEN_HDR}

${RUMP_GEN_HDR}: ${SYSCALL_SH}
	$(call if_changed,syscall)

arch/lkl/kernel/rump_syscalls.c: ${SYSCALL_SH} ${RUMP_GEN_HDR}
	$(call if_changed,syscall)


CFLAGS_rump_syscalls.o += -DRUMP_KERNEL_IS_LIBC

.NOTPARALLEL : arch/lkl/kernel/rump_syscalls.c ${RUMP_GEN_HDR}
