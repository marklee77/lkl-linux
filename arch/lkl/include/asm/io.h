#ifndef _ASM_LKL_IO_H
#define _ASM_LKL_IO_H

#include <asm/bug.h>

#ifndef outb
#define outb outb
static inline void outb(u8 v, u16 port)
{
	asm volatile("outb %0,%1" : : "a" (v), "dN" (port));
}
#endif

#ifndef outw
#define outw outw
static inline void outw(u16 v, u16 port)
{
	asm volatile("outw %0,%1" : : "a" (v), "dN" (port));
}
#endif

#ifndef outl
#define outl outl
static inline void outl(u32 v, u16 port)
{
	asm volatile("outl %0,%1" : : "a" (v), "dN" (port));
}
#endif

#ifndef inb
#define inb inb
static inline u8 inb(u16 port)
{
	u8 v;
	asm volatile("inb %1,%0" : "=a" (v) : "dN" (port));
	return v;
}
#endif

#ifndef inw
#define inw inw
static inline u16 inw(u16 port)
{
	u16 v;
	asm volatile("inw %1,%0" : "=a" (v) : "dN" (port));
	return v;
}
#endif

#ifndef inl
#define inl inl
static inline u32 inl(u16 port)
{
	u32 v;
	asm volatile("inl %1,%0" : "=a" (v) : "dN" (port));
	return v;
}
#endif


#define ioremap ioremap
static inline void __iomem *ioremap(phys_addr_t offset, size_t size)
{
	return (void __iomem *)(unsigned long)(offset);
}

#include <asm-generic/io.h>

#endif /* _ASM_LKL_IO_H */

