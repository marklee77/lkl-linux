/*
 * Rump hypercall interface for Linux
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <thehajime@gmail.com>
 */

#include <linux/sched.h>
#include <asm/types.h>
#include <asm/unistd.h>

#include "rump.h"

#define RUMP_SYSCALL0(_syscall)					\
	long rump___sysimpl_##_syscall(void)			\
	{							\
		int ret;					\
		long params[6];					\
		ret = lkl_syscall(__NR_##_syscall, params);	\
		if (ret < 0) {					\
			rumpuser_seterrno(ret);			\
			ret = -1;				\
		}						\
		return ret;					\
	}

#define RUMP_SYSCALL1(_syscall)					\
	long rump___sysimpl_##_syscall(long arg1)		\
	{							\
		int ret;					\
		long params[6];					\
		params[0] = (long)arg1;				\
		ret = lkl_syscall(__NR_##_syscall, params);	\
		if (ret < 0) {					\
			rumpuser_seterrno(ret);			\
			ret = -1;				\
		}						\
		return ret;					\
	}

#define RUMP_SYSCALL2(_syscall)					\
	long rump___sysimpl_##_syscall(long arg1, long arg2)	\
	{							\
		int ret;					\
		long params[6];					\
		params[0] = (long)arg1;				\
		params[1] = (long)arg2;				\
		ret = lkl_syscall(__NR_##_syscall, params);	\
		if (ret < 0) {					\
			rumpuser_seterrno(ret);			\
			ret = -1;				\
		}						\
		return ret;					\
	}

#define RUMP_SYSCALL3(_syscall)					\
	long rump___sysimpl_##_syscall(long arg1, long arg2,	\
				       long arg3)		\
	{							\
		int ret;					\
		long params[6];					\
		params[0] = (long)arg1;				\
		params[1] = (long)arg2;				\
		params[2] = (long)arg3;				\
		ret = lkl_syscall(__NR_##_syscall, params);	\
		if (ret < 0) {					\
			rumpuser_seterrno(ret);			\
			ret = -1;				\
		}						\
		return ret;					\
	}

#define RUMP_SYSCALL4(_syscall)					\
	long rump___sysimpl_##_syscall(long arg1, long arg2,	\
				       long arg3, long arg4)	\
	{							\
		int ret;					\
		long params[6];					\
		params[0] = (long)arg1;				\
		params[1] = (long)arg2;				\
		params[2] = (long)arg3;				\
		params[3] = (long)arg4;				\
		ret = lkl_syscall(__NR_##_syscall, params);	\
		if (ret < 0) {					\
			rumpuser_seterrno(ret);			\
			ret = -1;				\
		}						\
		return ret;					\
	}

#define RUMP_SYSCALL5(_syscall)					\
	long rump___sysimpl_##_syscall(long arg1, long arg2,	\
				       long arg3, long arg4,	\
				       long arg5)		\
	{							\
		int ret;					\
		long params[6];					\
		params[0] = (long)arg1;				\
		params[1] = (long)arg2;				\
		params[2] = (long)arg3;				\
		params[3] = (long)arg4;				\
		params[4] = (long)arg5;				\
		ret = lkl_syscall(__NR_##_syscall, params);	\
		if (ret < 0) {					\
			rumpuser_seterrno(ret);			\
			ret = -1;				\
		}						\
		return ret;					\
	}

#define RUMP_SYSCALL6(_syscall)					\
	long rump___sysimpl_##_syscall(long arg1, long arg2,	\
				       long arg3, long arg4,	\
				       long arg5, long arg6)	\
	{							\
		int ret;					\
		long params[6];					\
		params[0] = (long)arg1;				\
		params[1] = (long)arg2;				\
		params[2] = (long)arg3;				\
		params[3] = (long)arg4;				\
		params[4] = (long)arg5;				\
		params[5] = (long)arg6;				\
		ret = lkl_syscall(__NR_##_syscall, params);	\
		if (ret < 0) {					\
			rumpuser_seterrno(ret);			\
			ret = -1;				\
		}						\
		return ret;					\
	}

RUMP_SYSCALL3(socket);
