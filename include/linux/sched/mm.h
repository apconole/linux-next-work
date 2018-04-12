#ifndef _LINUX_SCHED_MM_H
#define _LINUX_SCHED_MM_H

#include <linux/sched.h>

#ifdef CONFIG_MEMBARRIER
enum {
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_READY	= (1U << 0),
	MEMBARRIER_STATE_SWITCH_MM			= (1U << 1),
};

static inline void membarrier_execve(struct task_struct *t)
{
	atomic_set(&t->mm->membarrier_state, 0);
}
#else
static inline void membarrier_execve(struct task_struct *t)
{
}
#endif

#endif /* _LINUX_SCHED_MM_H */
