#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <asm/host_ops.h>

#include "rump.h"

void __ndelay(unsigned long nsecs)
{
#ifdef LKL_TIMER
	unsigned long long start = lkl_ops->time();

	while (lkl_ops->time() < start + nsecs)
		;
#else
	struct timespec ts = ns_to_timespec(nsecs);
	rumpuser_clock_sleep(RUMPUSER_CLOCK_ABSMONO, ts.tv_sec, ts.tv_nsec);
#endif
}

void __udelay(unsigned long usecs)
{
	__ndelay(usecs * NSEC_PER_USEC);
}

void __const_udelay(unsigned long xloops)
{
	__udelay(xloops / 5);
}

void calibrate_delay(void)
{
}

void read_persistent_clock(struct timespec *ts)
{
	rumpuser_clock_gettime(RUMPUSER_CLOCK_RELWALL, (int64_t *)&ts->tv_sec,
			       &ts->tv_nsec);
}

static cycle_t clock_read(struct clocksource *cs)
{
#ifdef LKL_TIMER
	return lkl_ops->time();
#else
	struct timespec ts;
	rumpuser_clock_gettime(RUMPUSER_CLOCK_RELWALL, (int64_t *)&ts.tv_sec,
			       &ts.tv_nsec);

	return timespec_to_ns(&ts);
#endif
}

static struct clocksource clocksource = {
	.name	= "lkl",
	.rating = 499,
	.read	= clock_read,
	.flags	= CLOCK_SOURCE_IS_CONTINUOUS,
	.mask	= CLOCKSOURCE_MASK(64),
};

static void *timer;

static int timer_irq;

static void timer_fn(void *arg)
{
	lkl_trigger_irq(timer_irq, NULL);
}

static int clockevent_set_state_shutdown(struct clock_event_device *evt)
{
	if (timer) {
#ifdef LKL_TIMER
		lkl_ops->timer_free(timer);
#else
		rump_timer_cancel(timer);
#endif
		timer = NULL;
	}

	return 0;
}

static int clockevent_set_state_oneshot(struct clock_event_device *evt)
{
#ifdef LKL_TIMER
	timer = lkl_ops->timer_alloc(timer_fn, NULL);
	if (!timer)
		return -ENOMEM;
#endif
	return 0;
}

static irqreturn_t timer_irq_handler(int irq, void *dev_id)
{
	struct clock_event_device *dev = (struct clock_event_device *)dev_id;

	dev->event_handler(dev);

	return IRQ_HANDLED;
}

static int clockevent_next_event(unsigned long hz,
				 struct clock_event_device *evt)
{
	unsigned long ns = 1000000000 * hz / HZ;

#ifdef LKL_TIMER
	return lkl_ops->timer_set_oneshot(timer, ns);
#else
	/* FIXME: maybe will rewrite with rumpuer-based timer thread */
	timer = rump_add_timer(ns, timer_fn, NULL);
	return timer ? 0 : -1;
#endif
}

static struct clock_event_device clockevent = {
	.name			= "lkl",
	.features		= CLOCK_EVT_FEAT_ONESHOT,
	.set_state_oneshot	= clockevent_set_state_oneshot,
	.set_next_event		= clockevent_next_event,
	.set_state_shutdown	= clockevent_set_state_shutdown,
};

static struct irqaction irq0  = {
	.handler = timer_irq_handler,
	.flags = IRQF_NOBALANCING | IRQF_TIMER,
	.dev_id = &clockevent,
	.name = "timer"
};

void __init time_init(void)
{
	int ret;

#ifdef LKL_TIMER
	if (!lkl_ops->timer_alloc || !lkl_ops->timer_free ||
	    !lkl_ops->timer_set_oneshot || !lkl_ops->time) {
		pr_err("lkl: no time or timer support provided by host\n");
		return;
	}
#endif

	timer_irq = lkl_get_free_irq("timer");
	setup_irq(timer_irq, &irq0);

	ret = clocksource_register_khz(&clocksource, 1000000);
	if (ret)
		pr_err("lkl: unable to register clocksource\n");

	clockevents_config_and_register(&clockevent, HZ, 0, 0xffffffff);

	pr_info("lkl: time and timers initialized\n");
}
