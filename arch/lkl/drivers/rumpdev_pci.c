/*
 * rumprun PCI access (from src-netbsd/.../rumpdev_pci.c)
 */

/*
 * Copyright (c) 2013 Antti Kantee.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/types.h>

#include "pci_user.h"

/* from arch/x86/pci/common.c  */
void pcibios_fixup_bus(struct pci_bus *b)
{
	pci_read_bridge_bases(b);
}

/* drivers/pci/access.c
 *
 * @bus: PCI bus to scan
 * @devfn: slot number to scan (must have zero function.)
 */
void *rump_pci_map_bus(struct pci_bus *bus, unsigned int devfn, int where)
{
	unsigned long addr;

	addr =  (1<<31) | (bus->number<<16) | (PCI_SLOT(devfn) <<11) |
		(PCI_FUNC(devfn) <<8) | (where & 0xfc);

	/* FIXME: length? */
	return rumpcomp_pci_map(addr, 0);
}

int rump_pci_generic_read(struct pci_bus *bus, unsigned int devfn,
			  int where, int size, u32 *val)
{

	rumpcomp_pci_confread(bus->number, PCI_SLOT(devfn),
			      PCI_FUNC(devfn), where, val);
	if (size <= 2)
		*val = (*val >> (8 * (where & 3))) & ((1 << (size * 8)) - 1);

	return PCIBIOS_SUCCESSFUL;
}

int rump_pci_generic_write(struct pci_bus *bus, unsigned int devfn,
			    int where, int size, u32 val)
{
	u32 mask, tmp;

	if (size == 4) {
		rumpcomp_pci_confwrite(bus->number, PCI_SLOT(devfn),
				       PCI_FUNC(devfn), where, val);
		return PCIBIOS_SUCCESSFUL;
	} else {
		mask = ~(((1 << (size * 8)) - 1) << ((where & 0x3) * 8));
	}

	/* This brings the way much overhead though I picked this
	 * code from access.c.. maybe should come up with single
	 * write method to avoid that. */

	rumpcomp_pci_confread(bus->number, PCI_SLOT(devfn),
			      PCI_FUNC(devfn), where, &tmp);
	tmp &= mask;
	tmp |= val << ((where & 0x3) * 8);

	rumpcomp_pci_confwrite(bus->number, PCI_SLOT(devfn),
			       PCI_FUNC(devfn), where, tmp);

	return PCIBIOS_SUCCESSFUL;
}


#ifdef __HAVE_PCIIDE_MACHDEP_COMPAT_INTR_ESTABLISH
#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pciidereg.h>
#include <dev/pci/pciidevar.h>

void *
pciide_machdep_compat_intr_establish(device_t dev,
	const struct pci_attach_args *pa, int chan,
	int (*func)(void *), void *arg)
{
	pci_intr_handle_t ih;
	struct pci_attach_args mypa = *pa;

	mypa.pa_intrline = PCIIDE_COMPAT_IRQ(chan);
	if (pci_intr_map(&mypa, &ih) != 0)
		return NULL;
	return rumpcomp_pci_irq_establish(ih, func, arg);
}

__strong_alias(pciide_machdep_compat_intr_disestablish,pci_intr_disestablish);
#endif /* __HAVE_PCIIDE_MACHDEP_COMPAT_INTR_ESTABLISH */


struct rump_pci_sysdata {
	int domain; /* PCI domain */
};


/* from kernel/irq/manage.c */
#if 0
static int irq_thread(void *data)
{
	struct irqaction *action = data;
	struct irq_desc *desc = irq_to_desc(action->irq);
	irqreturn_t action_ret;

	action_ret = action->thread_fn(action->irq, action->dev_id);
	pr_info("IRQ handler returns %d\n", action_ret);

	return 0;
}

int request_threaded_irq(unsigned int irq, irq_handler_t handler,
			 irq_handler_t thread_fn, unsigned long irqflags,
			 const char *devname, void *dev_id)
{
	int rv;
	struct irqaction *action;

	rv = rumpcomp_pci_irq_map(0xff, 0xff, 0xff, irq, irq);

	action = kzalloc(sizeof(struct irqaction), GFP_KERNEL);
	if (!action)
		return -ENOMEM;

	action->handler = handler;
	action->thread_fn = thread_fn;
	action->flags = irqflags;
	action->name = devname;
	action->dev_id = dev_id;

	rumpcomp_pci_irq_establish(irq, irq_thread, action);
	return 0;
}
#endif

static int pci_lib_claim_resource(struct pci_dev *dev, void *data)
{
	int i;
	struct resource *r;

	for (i = 0; i < PCI_NUM_RESOURCES; i++) {
		r = &dev->resource[i];

		if (!r->parent && r->start && r->flags) {
			dev_info(&dev->dev, "claiming resource %s/%d\n",
				pci_name(dev), i);
			if (pci_claim_resource(dev, i)) {
				dev_err(&dev->dev, "Could not claim resource %s/%d! "
					"Device offline. Try using e820_host=1 in the guest config.\n",
					pci_name(dev), i);
			}
		}
	}

	return 0;
}

struct pci_ops rump_pci_root_ops = {
	.map_bus = rump_pci_map_bus,
	.read = rump_pci_generic_read,
	.write = rump_pci_generic_write,
};


static int __init
rump_pci_init(void)
{
	struct pci_bus *bus;
	struct rump_pci_sysdata *sd;
	int busnum = 0;
	LIST_HEAD(resources);

	sd = kzalloc(sizeof(*sd), GFP_KERNEL);
	if (!sd) {
		printk(KERN_ERR "PCI: OOM, skipping PCI bus %02x\n", busnum);
		return -1;
	}

	printk(KERN_INFO "PCI: root bus %02x: using default resources\n", busnum);
	bus = pci_scan_bus(busnum, &rump_pci_root_ops, sd);
	if (!bus) {
		pci_free_resource_list(&resources);
		kfree(sd);
		return -1;
	}
	pci_walk_bus(bus, pci_lib_claim_resource, NULL);
	pci_bus_add_devices(bus);

	return 0;
}
device_initcall(rump_pci_init);
