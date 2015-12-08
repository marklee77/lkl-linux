/*
 * IO routine using rumpkernel hypercall
 * Copyright (c) 2015 Hajime Tazaki
 *
 * Author: Hajime Tazaki <thehajime@gmail.com>
 */

#include <linux/compiler.h>
#include <linux/kernel.h>

/* FIXME: need to add a switch #ifdef IOSPACE_SUPPORTED as
   NetBSD rump kernel does */
u8 rump_io_readb(const volatile void __iomem *addr)
{
	u8 v;
	u16 mem = (unsigned long)addr;
#ifdef X86
	asm volatile("inb %1,%0" : "=a"(v) : "d"(mem));
#endif
	return v;
}

u16 rump_io_readw(const volatile void __iomem *addr)
{
	u16 v;
	u16 mem = (unsigned long)addr;
#ifdef X86
	asm volatile("in %1,%0" : "=a"(v) : "d"(mem));
#endif
	return v;
}

u32 rump_io_readl(const volatile void __iomem *addr)
{
	u32 v;
	u16 mem = (unsigned long)addr;
#ifdef X86
	asm volatile("inl %1,%0" : "=a"(v) : "d"(mem));
#endif
	return v;
}

u64 rump_io_readq(const volatile void __iomem *addr)
{
	/* XXX: not implemented yet */
	panic("rump_io_readq");
	return 0;
}

void rump_io_writeb(u8 value, const volatile void __iomem *addr)
{
	u16 mem = (unsigned long)addr;
#ifdef X86
	asm volatile("outb %0, %1" :: "a"(value), "d"(mem));
#endif
}

void rump_io_writew(u16 value, const volatile void __iomem *addr)
{
	u16 mem = (unsigned long)addr;
#ifdef X86
	asm volatile("out %0, %1" :: "a"(value), "d"(mem));
#endif
}

void rump_io_writel(u32 value, const volatile void __iomem *addr)
{
	u16 mem = (unsigned long)addr;
#ifdef X86
	asm volatile("outl %0, %1" :: "a"(value), "d"(mem));
#endif
}

void rump_io_writeq(u64 value, const volatile void __iomem *addr)
{
	/* XXX: not implemented yet */
	panic("rump_io_readq");
}
