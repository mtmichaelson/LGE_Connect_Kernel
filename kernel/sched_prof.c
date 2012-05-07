#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/utsname.h>

#include <linux/sched_prof.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/net.h>

extern void wakeup_sysprofd(int cpu);

int stop_wait = 0;
static DECLARE_WAIT_QUEUE_HEAD(trace_stop_wait);

#define SEQ_printf(m, x...)			\
 do {						\
	if (m)					\
		seq_printf(m, x);		\
	else					\
		printk(x);			\
 } while (0)


int task_trace_flag = 0;
EXPORT_SYMBOL(task_trace_flag);

int trace_has_started = 0;

DEFINE_PER_CPU(trace_info_t, task_trace);
DEFINE_PER_CPU(unsigned int, gseq_no);
DEFINE_PER_CPU(extra_info_t, int_data);

DEFINE_MUTEX(kevent_lock);
int kevent_cnt = 0;
kevent_t *kevent_log;

int prepare_task_tracing(void);
void stop_task_tracing(void);

int prepare_task_tracing(void)
{
	int i;
	trace_info_t *ti;

	for (i = 0; i < NR_CPUS; i++) {
		ti = &per_cpu(task_trace, i);
		if (ti->trow == NULL) {
			pr_info("allocate memory of cpu%d array\n", i);
			ti->trow = (trow_t *)vmalloc(sizeof(trow_t) * MAX_TRACE_IDX);
			if (ti->trow == NULL) {
				pr_err("Can't allocate memory, Profiling Off\n");
				return -ENOMEM;
			}
		}
		if (ti->trow)
			memset(ti->trow, 0, sizeof(trow_t) * MAX_TRACE_IDX);

		per_cpu(ksend_count, i) = 0;
		atomic_set(&ti->index, 0);
		atomic_set(&ti->read_index, 0);
		ti->idx_flag = 0;
		ti->read_idx_flag = 0;
		per_cpu(gseq_no, i) = 0;
	}
	return 0;

#if 0
	if (kevent_log == NULL) {
		pr_info("allocate kevent_log\n");
		kevent_log = vmalloc(sizeof(*kevent_log) * MAX_KEVENT);
		if (kevent_log == NULL) {
			pr_info("Can't allocate kevent memory, Profiling Off\n");
			return;
		}
		memset(kevent_log, 0, sizeof(*kevent_log) * MAX_KEVENT);
	}

	task_trace_flag = 1;

	for (i = 0; i < NR_CPUS; i++) {
		pr_info("wake_up sysprofd[%d] \n", i);
		wakeup_sysprofd(i);
	}
	trace_has_started = 1;
	return 0;
#endif
}

#ifdef CONFIG_LG_SYSPROF_KEVENT
int prepare_kevent_tracing(void)
{
	if (kevent_log == NULL) {
		pr_info("allocate kevent_log\n");
		kevent_log = vmalloc(sizeof(*kevent_log) * MAX_KEVENT);
		if (kevent_log == NULL) {
			pr_err("Can't allocate kevent memory, Profiling Off\n");
			return -ENOMEM;
		}
		memset(kevent_log, 0, sizeof(*kevent_log) * MAX_KEVENT);
	}
	return 0;
}
#endif

void init_task_tracing(void)
{
	int i, ret = 0;

	ret = prepare_task_tracing();
	if (ret)
		return;

#ifdef CONFIG_LG_SYSPROF_KEVENT
	ret = prepare_kevent_tracing();
	if (ret)
		return;
#endif

	task_trace_flag = 1;

	for (i = 0; i < NR_CPUS; i++) {
		pr_info("wake_up sysprofd[%d] \n", i);
		wakeup_sysprofd(i);
	}

	trace_has_started = 1;

}

#ifdef CONFIG_LG_SYSPROF_KEVENT
void sysprof_kevent_log(char *category, char *name, char *desc)
{
	mutex_lock(&kevent_lock);
	if (kevent_cnt == MAX_KEVENT - 1) {
		mutex_unlock(&kevent_lock);
		pr_info("SYSPROF EVENT LOG BUFFER FULL(%d events)\n", MAX_KEVENT);
		return;
	}

	kevent_log[kevent_cnt].time = ktime_to_ns(ktime_get());
	memcpy(kevent_log[kevent_cnt].category, category, 31);
	memcpy(kevent_log[kevent_cnt].name, name, 31);
	memcpy(kevent_log[kevent_cnt].desc, desc, 31);
	kevent_cnt++;

	mutex_unlock(&kevent_lock);
}
EXPORT_SYMBOL(sysprof_kevent_log);
#endif

void stop_task_tracing(void)
{
	DECLARE_WAITQUEUE(wait, current);

	task_trace_flag = 0;

	stop_wait = 1;
	/* wait for syncing all profile log */
	add_wait_queue(&trace_stop_wait, &wait);
	set_current_state(TASK_INTERRUPTIBLE);
	schedule();
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&trace_stop_wait, &wait);
	stop_wait = 0;
}

void trace_done_wakeup(void)
{
	int i;
	trace_info_t *ti;

	for (i = 0; i < NR_CPUS; i++) {
		ti = &per_cpu(task_trace, i);
		if (ti->trow) {
			vfree(ti->trow);
			ti->trow = NULL;
			pr_info("free memory of cpu%d array\n", i);
		}
	}

#ifdef CONFIG_LG_SYSPROF_KEVENT
	if (kevent_log) {
		vfree(kevent_log);
		kevent_log = NULL;
		pr_info("free kevent_log\n");
	}
#endif

	wake_up(&trace_stop_wait);
}
EXPORT_SYMBOL(trace_done_wakeup);

#if 0
static int task_trace_show(struct seq_file *m, void *v)
{
	int i, idx, cpu, prio;
	unsigned int state_flags, nr_running;
	trace_info_t *ti;
	pid_t	pid;
	struct rq *rq;

	if (!m)
		return 0;

	if (!trace_has_started)
		return 0;

	SEQ_printf(m, "Task Trace Version: v0.0.1, %s %.*s\n",
			init_utsname()->release,
			(int)strcspn(init_utsname()->version, " "),
			init_utsname()->version);
	for_each_online_cpu(cpu) {
		ti = &per_cpu(task_trace, cpu);
		rq = cpu_rq(cpu);
		idx = atomic_read(&ti->index);
		if (idx == 0) {
			idx = MAX_TRACE_IDX;
		}
		idx--;
		SEQ_printf(m, "\n\n======== CPU : %d ========\n\n", cpu);
		SEQ_printf(m, "%-20s: %Ld.%06ld, %Ld.%06ld\n", "rq->clock", SPLIT_NS(rq->clock), SPLIT_NS(ktime_to_ns(ktime_get())));
		SEQ_printf(m, "%-6s %-8s %-16s %-8s %-16s %-4s %-4s %-4s %-4s\n", "idx", "pid", "name", "priority", "start_time", "NR", "M", "S", "W");
		for (i = 0; i < MAX_TRACE_IDX; i++) {
			pid = ti->trow[idx].pid;
			prio = ti->trow[idx].prio;
			state_flags = ti->trow[idx].flags;
			nr_running = ti->trow[idx].flags & NR_TASK_MASK;
			if (pid == 0xFFFFFFFF) {
				if (idx == 0)
					idx = MAX_TRACE_IDX;
				idx--;
				continue;
			}

			SEQ_printf(m, "%-6d %-8d %-16s %-8d %lld.%06ld %4d %4d %4d %4d\n %8d %4d %8d %4d\n", idx,
					pid, ti->trow[idx].name, prio, SPLIT_NS(ti->trow[idx].start_time), nr_running,
					(state_flags & TASK_MIGRATION)?1:0, (state_flags & TASK_SLEEP)?1:0, (state_flags & TASK_WAKEUP)?1:0,
					ti->trow[idx].int_usage, ti->trow[idx].int_count,
					ti->trow[idx].pf_usage, ti->trow[idx].pf_count);

			if (idx == 0)
				idx = MAX_TRACE_IDX;
			idx--;
		}
	}
	return 0;
}

static int task_trace_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, task_trace_show, NULL);
}

static const struct file_operations task_trace_fops = {
	.open		= task_trace_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init init_task_trace(void)
{
	struct proc_dir_entry *pe;

	pe = proc_create("task_trace_data", 0444, NULL, &task_trace_fops);
	if (!pe)
		return -ENOMEM;

	return 0;
}

__initcall(init_task_trace);
#endif

static ssize_t
task_trace_flag_write(struct file *file, const char __user *buf,
		size_t count, loff_t *offset)
{

	if (!task_trace_flag && !strncmp(buf, "1", count - 1)) {
		init_task_tracing();
		pr_info("task monitoring on\n");
	} else if (task_trace_flag && !strncmp(buf, "0", count - 1)) {
		stop_task_tracing();
		pr_info("task monitoring off\n");
	} else  {
		pr_info("task trace alreay start/stop\n");
	}
	return count;
}

static int task_trace_flag_show(struct seq_file *m, void *v)
{
	int i;
	trace_info_t *ti;

	SEQ_printf(m, "%d\n", task_trace_flag);
	for (i = 0; i < NR_CPUS; i++) {
		ti = &per_cpu(task_trace, i);
		SEQ_printf(m, "%ld ", per_cpu(ksend_count, i));
		SEQ_printf(m, "%d %d", atomic_read(&ti->index), atomic_read(&ti->read_index));
		SEQ_printf(m, "\n");
	}

	return 0;
}

static int task_trace_flag_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, task_trace_flag_show, NULL);
}

static const struct file_operations task_trace_flag_fops = {
	.open		= task_trace_flag_open,
	.read		= seq_read,
	.write		= task_trace_flag_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init init_task_trace_flag(void)
{
	struct proc_dir_entry *pe;

	pe = proc_create("task_trace_flag", 0644, NULL, &task_trace_flag_fops);
	if (!pe)
		return -ENOMEM;

	return 0;
}

__initcall(init_task_trace_flag);

#ifdef USE_NETWORK
extern char sysprof_server[];

static ssize_t
sysprof_server_write(struct file *file, const char __user *buf,
		size_t count, loff_t *offset)
{
	memset(sysprof_server, 0, IPADDR_LEN);
	memcpy(sysprof_server, buf, count);
	return count;
}
static int sysprof_server_show(struct seq_file *m, void *v)
{
	SEQ_printf(m, "%s\n", sysprof_server);
	return 0;
}

static int sysprof_server_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, sysprof_server_show, NULL);
}

static const struct file_operations sysprof_server_fops = {
	.open		= sysprof_server_open,
	.read		= seq_read,
	.write		= sysprof_server_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init init_sysprof_server(void)
{
	struct proc_dir_entry *pe;

	pe = proc_create("sysprof_server", 0644, NULL, &sysprof_server_fops);
	if (!pe)
		return -ENOMEM;

	return 0;
}

__initcall(init_sysprof_server);
#endif

void trace_sched_sysprof(int cpu, struct rq *rq, struct task_struct *prev, struct task_struct *next)
{
	int idx, read_idx, prev_idx;
	trace_info_t *ti;
	extra_info_t *idata;

	ti = &per_cpu(task_trace, cpu);
	idata = &per_cpu(int_data, cpu);

	idx = atomic_read(&ti->index);
	read_idx = atomic_read(&ti->read_index);

	if ((idx == read_idx) && (ti->idx_flag != ti->read_idx_flag)) {
		pr_info("debug cpu %d idx %d flag %d write and read idx is same. memory may be overwritten\n", cpu, idx, ti->idx_flag);
	}

	prev_idx = idx - 1;
	if (idx == 0)
		prev_idx = MAX_TRACE_IDX - 1;

	if (prev->state_flags & TASK_SLEEP) {
		if (ti->trow[prev_idx].pid != 0xFFFFFFFF)
			ti->trow[prev_idx].flags |= TASK_SLEEP;
		prev->state_flags &= ~TASK_SLEEP;
	}

	ti->trow[idx].pid = next->pid;
	ti->trow[idx].prio = next->prio;

	/* TODO : check */
	memset(ti->trow[idx].name, 0, TASK_COMM_LEN);
	if (!strncmp(&next->comm[strlen(next->comm)], (const char *)"\0", sizeof("\0"))) {
		memcpy(ti->trow[idx].name, next->comm, strlen(next->comm) - 1);
	} else {
		memcpy(ti->trow[idx].name, next->comm, strlen(next->comm));
	}

//	ti->trow[idx].start_time = ktime_to_ns(ktime_get_real());
	ti->trow[idx].start_time = ktime_to_ns(ktime_get());
	ti->trow[idx].flags = rq->nr_running | next->state_flags;

	ti->trow[idx].int_count = atomic_read(&idata->count);
	ti->trow[idx].int_usage = idata->sum;

	/* initialize */
	memset(idata, 0, sizeof(extra_info_t));

	/* tmp */
	ti->trow[idx].seq_no = per_cpu(gseq_no, cpu)++;
	/**/

	next->state_flags &= ~(TASK_MIGRATION | TASK_WAKEUP);

	if (idx == (MAX_TRACE_IDX - 1)) {
		pr_info("cpu %d idx %d reached end of buffer, turn around\n", cpu, idx);
		atomic_set(&ti->index, 0);
		ti->idx_flag ^= 0x01;   /* toggle flag for wrap around of write index */
	}
	else
		atomic_inc(&ti->index);
}
#undef SEQ_printf
