#ifndef _ASM_LKL_IO_H
#define _ASM_LKL_IO_H

#include <asm/bug.h>
#include "rump.h"

#define __raw_readb __raw_readb
static inline u8 __raw_readb(const volatile void __iomem *addr)
{
	return rump_io_readb(addr);
}

#define __raw_readw __raw_readw
static inline u16 __raw_readw(const volatile void __iomem *addr)
{
	return rump_io_readw(addr);
}

#define __raw_readl __raw_readl
static inline u32 __raw_readl(const volatile void __iomem *addr)
{
	return rump_io_readl(addr);
}

#ifdef CONFIG_64BIT
#define __raw_readq __raw_readq
static inline u64 __raw_readq(const volatile void __iomem *addr)
{
	return rump_io_readq(addr);
}
#endif /* CONFIG_64BIT */

#define __raw_writeb __raw_writeb
static inline void __raw_writeb(u8 value, volatile void __iomem *addr)
{
	rump_io_writeb(value, addr);
}

#define __raw_writew __raw_writew
static inline void __raw_writew(u16 value, volatile void __iomem *addr)
{
	rump_io_writew(value, addr);
}

#define __raw_writel __raw_writel
static inline void __raw_writel(u32 value, volatile void __iomem *addr)
{
	rump_io_writel(value, addr);
}

#ifdef CONFIG_64BIT
#define __raw_writeq __raw_writeq
static inline void __raw_writeq(u64 value, volatile void __iomem *addr)
{
	rump_io_writeq(value, addr);
}
#endif /* CONFIG_64BIT */


#define ioremap ioremap
static inline void __iomem *ioremap(phys_addr_t offset, size_t size)
{
	return (void __iomem *)(unsigned long)(offset);
}

#include <asm-generic/io.h>

#endif /* _ASM_LKL_IO_H */

