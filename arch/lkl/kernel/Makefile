extra-y := vmlinux.lds

obj-y = setup.o threads.o irq.o time.o syscalls.o misc.o mem.o console.o \
	rump.o rump-host.o rump-sysproxy.o rump_syscalls.o

UNISTD_HDR = arch/lkl/include/uapi/asm/unistd.h
SYSCALL_SH = arch/lkl/scripts/syscall_wrapper.sh
RUMP_GEN_HDR = arch/lkl/include/generated/linux/rump_syscalls.h
quiet_cmd_syscall = CALL    $@
      cmd_syscall = $(CONFIG_SHELL) $< ${UNISTD_HDR} $@ ${RUMP_GEN_HDR}

arch/lkl/kernel/rump_syscalls.c:  ${SYSCALL_SH}
	$(call if_changed,syscall)
