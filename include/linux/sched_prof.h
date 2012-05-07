#ifndef _SCHED_PROF_H
#define _SCHED_PROF_H

#include <linux/sched.h>

#define FALSE	0
#define TRUE	1

#define TASK_FLAGS_SHIFT_BIT    (24)
#define TASK_MIGRATION          (0x1 << TASK_FLAGS_SHIFT_BIT)
#define TASK_SLEEP              (0x2 << TASK_FLAGS_SHIFT_BIT)
#define TASK_WAKEUP             (0x4 << TASK_FLAGS_SHIFT_BIT)

#define NR_TASK_MASK			(0x0000FFFF)

#define MAX_TRACE_IDX_BIT		(15)	/* 1 << 15 = 32768 */
//#define MAX_TRACE_IDX_BIT		(14)	/* 1 << 14 = 16384 */
#define MAX_SEND_IDX_BIT		(9)

#define MAX_TRACE_IDX			(1 << MAX_TRACE_IDX_BIT)/* 32768 */
#define SYSPROF_HIGH_WMARK		(MAX_TRACE_IDX >> 1)	/* half of MAX_TRACE_IDX */

#define MAX_SEND_IDX			(1 << MAX_SEND_IDX_BIT)	/* 512 */
#define MAX_SEND_SIZE(type)		(MAX_SEND_IDX * sizeof(type))

#define SYSPROF_UDS_PATH		"/dev/socket/lgprofd"
#define SYSPROF_KEVENT_PORT		(15000)
#define SYSPROF_PORT			(SYSPROF_KEVENT_PORT + 1)
#define SYSPROF_CPU_PORT(cpu)	(SYSPROF_PORT + cpu)

#define IPADDR_LEN				(16)
#define TRACE_FILENAME			"/mnt/sdcard/trace_raw"

#define MAX_KEVENT				(128)
#define KEVENT_FILENAME			"/mnt/sdcard/kevent_raw"

#define USE_DSOCKET

typedef struct trace_row trow_t;
struct trace_row {
	unsigned int	seq_no;		/* temporary field */
	pid_t pid;
	int	prio;
	char	name[TASK_COMM_LEN];
	unsigned int flags;
	u64 start_time;
	unsigned int int_count;	/* interrupt count */
	unsigned int int_usage;	/* time spent on ISR */
	unsigned int pf_count;	/* page-fault count */
	unsigned int pf_usage;	/* time spent on page-fault */
};

typedef struct trace_info trace_info_t;
struct trace_info {
	atomic_t	index;
	atomic_t	read_index;
	short int	idx_flag;
	short int	read_idx_flag;
	trow_t 		*trow;
};

typedef struct extra_info extra_info_t;
struct extra_info {
	spinlock_t	lock;
	long long start_time;
	unsigned int sum;
	atomic_t count;
};

typedef struct kernel_event kevent_t;
struct kernel_event {
	long long time;
	char category[32];
	char name[32];
	char desc[64];
};

extern int check_write_condition(int cpu, int *cur_rp, int *cur_wp);
extern int task_trace_flag;
DECLARE_PER_CPU(unsigned long, ksend_count);
DECLARE_PER_CPU(unsigned int, gseq_no);
DECLARE_PER_CPU(trace_info_t, task_trace);

#endif /* _SCHED_PROF_H */
