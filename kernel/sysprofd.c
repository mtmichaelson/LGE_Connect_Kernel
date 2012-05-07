#define pr_fmt(fmt)     "sysprofd: " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/un.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/cpu.h>

#include <linux/sched_prof.h>

#define KSYSPROF_DAEMON	"ksysprofd"
#define KSYSPROF_DEFAULT_TIMEOUT	(HZ/2)

extern int task_trace_flag;
extern int stop_wait;
extern void trace_done_wakeup(void);

#if defined (USE_NETWORK) || defined (USE_DSOCKET)
static DEFINE_PER_CPU(struct socket *, socket);
struct socket *kevt_socket;
#endif

extern struct file *fget(int fd);
extern void fput(struct file *file);

#ifdef CONFIG_LG_SYSPROF_KEVENT
extern kevent_t *kevent_log;
extern int kevent_cnt;
extern struct mutex kevent_lock;
#endif

DEFINE_PER_CPU(unsigned long, ksend_count);
static DEFINE_PER_CPU(int, trace_fd);
static DEFINE_PER_CPU(struct task_struct *, sysprofd);
char sysprof_server[IPADDR_LEN];

#if defined (USE_FILESYSTEM)
#define kclose(fd) { \
	mm_segment_t old_fs = get_fs(); \
	set_fs(KERNEL_DS); \
	sys_close(fd) \
	set_fs(old_fs); \
}

#define _kopen(filename, flags, mode)	sys_open(filename, flags, mode)

static __attribute__((always_inline)) int kopen(char *filename, int flags, int mode)
{
	int fd;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	fd = _kopen(filename, flags, mode);
	set_fs(old_fs);
	return fd;
}
#endif

static int _kwrite(int fd, char *buf, size_t size)
{
	size_t remain = size;
	int wcnt = 0, total_wcnt = 0;
	
	do {
		wcnt = sys_write(fd, buf, remain);
		if (wcnt < 0) {
			pr_err("kernel file write error(%d) wsize %d remain %d\n", wcnt, size, remain);
			/* TODO: handle error code */
			break;
		}
		remain -= wcnt;
		total_wcnt += wcnt;
	} while (remain > 0);

	return total_wcnt?total_wcnt:wcnt;
}

static __attribute__((always_inline)) int kwrite(int fd, char *buf, size_t size)
{
	int wcnt = 0;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	wcnt = _kwrite(fd, buf, size);
	set_fs(old_fs);

	return wcnt;
}

static inline int get_used_idx(int cur_rp, int cur_wp, int *dist_to_end)
{
	int remain_idx = cur_wp - cur_rp;

	if (remain_idx >= 0) {
		*dist_to_end = 0;
	} else {
		remain_idx += MAX_TRACE_IDX;
		*dist_to_end = MAX_TRACE_IDX - cur_rp;
	}
	return remain_idx;
}

static void write_log(int cpu, int fd, int cur_rp, int cur_wp)
{
	int ret, wrap_around = FALSE,
		sizeof_trow = sizeof(trow_t),
		write_idx, remain_idx,
		dist_to_end = 0;		/* distance to end idx */
	size_t wsize = 0;
	char *rp, *start;
	char *buf;
	trace_info_t *ti = &per_cpu(task_trace, cpu);

	rp = (char *)&ti->trow[cur_rp],
	start = (char *)&ti->trow[0];

	remain_idx = get_used_idx(cur_rp, cur_wp, &dist_to_end);

	if (dist_to_end)
		ti->read_idx_flag ^= 0x01;

	while (dist_to_end > 0) {
		wrap_around = TRUE;
		buf = rp;

		if (dist_to_end >= MAX_SEND_IDX) {
			write_idx = MAX_SEND_IDX;
		} else {
			write_idx = dist_to_end;
		}
//		pr_info("write 1th: comm %s cpu %d write_unit %d write_size %d seqno %u\n", current->comm, cpu, write_idx, wsize, ((trow_t *)rp)->seq_no);
		wsize = write_idx * sizeof_trow;
		ret = kwrite(fd, buf, wsize);
		if (ret < 0)
			pr_err("cpu[%d] kernel file write error(%d:%d)\n", cpu, ret, __LINE__);

		per_cpu(ksend_count, cpu)++;
		remain_idx -= write_idx;
		dist_to_end -= write_idx;
		cur_rp += write_idx;
		if (cur_rp == MAX_TRACE_IDX)
			cur_rp = 0;

		rp = (char *)&ti->trow[cur_rp];
		atomic_set(&ti->read_index, cur_rp);
	}

	if (dist_to_end != 0) {
		/* TODO: error */
	}

	if (wrap_around == TRUE)
		rp = start;

	while (remain_idx > 0) {
		buf = rp;

		if (remain_idx >= MAX_SEND_IDX) {
			write_idx = MAX_SEND_IDX;
		} else {
			write_idx = remain_idx;
		}

//		pr_info("write 2th: comm %s cpu %d write_unit %d write_size %d seqno %u\n", current->comm, cpu, write_idx, wsize, ((trow_t *)rp)->seq_no);
		wsize = write_idx * sizeof_trow;
		ret = kwrite(fd, buf, wsize);
		if (ret < 0)
			pr_err("cpu[%d] kernel file write error(%d:%d)\n", cpu, ret, __LINE__);

		per_cpu(ksend_count, cpu)++;
		remain_idx -= write_idx;
		cur_rp += write_idx;
		rp = (char *)&ti->trow[cur_rp];
		atomic_set(&ti->read_index, cur_rp);
	}
}


static int __check_write_condition(int cur_rp, int cur_wp)
{
	int ret = FALSE;
	int haveto_write;

	haveto_write = cur_wp - cur_rp;
	if (haveto_write < 0) {
		haveto_write += MAX_TRACE_IDX;
	}
	if (haveto_write > SYSPROF_HIGH_WMARK) {
		ret = TRUE;
	}
	return ret;
}

/* get current read / write index of trace data
 * return value
 * if read / write index is same, then return TRUE. */
static inline int check_current_position(int cpu, int *cur_rp, int *cur_wp)
{
	trace_info_t *ti = &per_cpu(task_trace, cpu);

	*cur_rp = atomic_read(&ti->read_index);
	*cur_wp = atomic_read(&ti->index);
	return (*cur_rp == *cur_wp);
}

int check_write_condition(int cpu, int *cur_rp, int *cur_wp)
{
	int ret = FALSE;

	check_current_position(cpu, cur_rp, cur_wp);

	ret = __check_write_condition(*cur_rp, *cur_wp);

	return ret;
}

typedef struct kern_sock kern_sock_t;
struct kern_sock {
	int family;
	int type;
	int protocol;
	union {
		struct sockaddr_in in_addr;
		struct sockaddr_un un_addr;
	} d;
};

int socket_conn(kern_sock_t *ksocket, struct socket **sock, int *fd)
{
	int ret = 0;
	int family = ksocket->family;
	int type = ksocket->type;
	int protocol = ksocket->protocol;
	int addr_size = 0;
	struct sockaddr *dest_addr;

	if (family == AF_UNIX) {
		dest_addr = (struct sockaddr *)&ksocket->d.un_addr;
		addr_size = sizeof(typeof(ksocket->d.un_addr));
	} else {
		dest_addr = (struct sockaddr *)&ksocket->d.in_addr;
		addr_size = sizeof(typeof(ksocket->d.in_addr));
	}

	ret = sock_create_kern(family, type, protocol, sock);
	if (ret < 0) {
		pr_err("Error(%d) during creation of socket; terminating \n", ret);
		return ret;
	}
	ret = kernel_connect(*sock, dest_addr, addr_size, O_RDWR);
	if (ret < 0) {
		pr_err("Error(%d) during socket connection; terminating \n", ret);
		return ret;
	}

	*fd = sock_map_fd(*sock, type & (O_CLOEXEC | O_NONBLOCK));
	if (*fd < 0) {
		pr_err("Error during sock_map_fd; terminating \n");
		sock_release(*sock);
		return -ENOENT;
	}
	return 0;
}

/* use file or socket to carry profile data */
int prepare_prof_data_container(int cpu)
{
	int ret = 0;
	kern_sock_t ksocket;

#if defined (USE_NETWROK)
	ksocket.family = AF_INET;
	#ifdef USE_UDP
	ksocket.type = SOCK_DGRAM;
	ksocket.protocol = IPPROTO_UDP;
	#else
	ksocket.type = SOCK_STREAM;
	ksocket.protocol = IPPROTO_TCP;
	#endif

	memset(&ksocket.d.in_addr, 0, sizeof(ksocket.d.in_addr));
	ksocket.d.in_addr.sin_family = AF_INET;
	ksocket.d.in_addr.s_addr = in_aton(sysprof_server);
	ksocket.d.in_addr.sin_port = htons(SYSPROF_CPU_PORT(cpu));

//	ret = socket_conn(&ksocket, &kevt_socket, fd);
	ret = socket_conn(&ksocket, &per_cpu(socket, cpu), fd);
	if (ret < 0)
		return ret;

	pr_info("%s %s socket for data is created \n", current->comm,
			(ksocket.family == AF_UNIX)?"Domain":"Inet");

#elif defined (USE_DSOCKET)
	int magic_key = 0xBADFEED0 + cpu;

	ksocket.family = AF_UNIX;
	ksocket.type = SOCK_STREAM;
	ksocket.protocol = IPPROTO_IP;
	memset(&ksocket.d.un_addr, 0, sizeof(ksocket.d.un_addr));
	ksocket.d.un_addr.sun_family = AF_UNIX;
	sprintf(ksocket.d.un_addr.sun_path, "%s", SYSPROF_UDS_PATH);

//	ret = socket_conn(&ksocket, &socket[cpu], &trace_fd[cpu]);
	ret = socket_conn(&ksocket, &per_cpu(socket, cpu), &per_cpu(trace_fd, cpu));
	if (ret < 0)
		return ret;

	pr_info("%s %s socket for data is created \n", current->comm,
			(ksocket.family == AF_UNIX)?"Domain":"Inet");

	/* send magic number to announce that it is socket for kevent */
//	ret = kwrite(trace_fd[cpu], (char *)&magic_key, sizeof(int));
	ret = kwrite(per_cpu(trace_fd, cpu), (char *)&magic_key, sizeof(int));
	if (ret < 0) {
		pr_err("cpu[%d], data magic_key send error(%d)\n", cpu, ret);
		/* TODO: handle error code */
	}

#elif defined (USE_FILESYSTEM)
	char filename[256];

	sprintf(filename, "%s%d", TRACE_FILENAME, cpu);
//	trace_fd[cpu] = kopen(filename, O_CLOEXEC | O_RDWR | O_CREAT | O_LARGEFILE | O_TRUNC, 0755);
	per_cpu(trace_fd, cpu) = kopen(filename, O_CLOEXEC | O_RDWR | O_CREAT | O_LARGEFILE | O_TRUNC, 0755);
	if (per_cpu(trace_fd, cpu) < 0) {
		pr_err("Error during file open \n");
		return -EFAULT;
	}
	pr_info("File(%s:%d) is opened\n", filename, per_cpu(trace_fd, cpu));

#endif
	return 0;
}

int prepare_kevent_data_container(int cpu, int *fd)
{
	kern_sock_t ksocket;
	int ret = 0;

#if defined (USE_NETWORK)
	ksocket.family = AF_INET;
	#ifdef USE_UDP
	ksocket.type = SOCK_DGRAM;
	ksocket.protocol = IPPROTO_UDP;
	#else
	ksocket.type = SOCK_STREAM;
	ksocket.protocol = IPPROTO_TCP;
	#endif
	memset(&ksocket.d.in_addr, 0, sizeof(ksocket.d.in_addr));
	ksocket.d.in_addr.sin_family = AF_INET;
	ksocket.d.in_addr.s_addr = in_aton(sysprof_server);
	ksocket.d.in_addr.sin_port = htons(SYSPROF_KEVENT_PORT);

	socket_conn(&ksocket, &kevt_socket, fd);

#elif defined (USE_DSOCKET)
	int magic_key = 0xBADFEEDF;

	ksocket.family = AF_UNIX;
	ksocket.type = SOCK_STREAM;
	ksocket.protocol = IPPROTO_IP;
	memset(&ksocket.d.un_addr, 0, sizeof(ksocket.d.un_addr));
	ksocket.d.un_addr.sun_family = AF_UNIX;
	sprintf(ksocket.d.un_addr.sun_path, "%s", SYSPROF_UDS_PATH);

	ret = socket_conn(&ksocket, &kevt_socket, fd);
	if (ret < 0) {
		return -EFAULT;
	}
	pr_info("%s %s socket for kevent is created \n", current->comm,
			(ksocket.family == AF_UNIX)?"Domain":"Inet");

	/* send magic number to announce that it is socket for kevent */
	ret = kwrite(*fd, (char *)&magic_key, sizeof(int));
	if (ret < 0) {
		pr_err("cpu[%d] kevent magic_key send error(%d)\n", cpu, ret);
		/* TODO: handle error code */
	}

#elif defined (USE_FILESYSTEM)
	char kevt_filename[256];

	if (cpu != 0) {
		return -EFAULT;
	}
	sprintf(kevt_filename, "%s", KEVENT_FILENAME);
	*fd = kopen(kevt_filename, O_APPEND | O_CLOEXEC | O_RDWR | O_CREAT | O_TRUNC, 0755);
	if (*fd < 0) {
		pr_err("Error during file open \n");
		return -EFAULT;
	}
	pr_info("Kevent Log File(%s:%d) is opened\n", kevt_filename, *fd);
#endif
	return 0;
}

void clean_prof_data_container(int cpu)
{

#if defined (USE_NETWORK) || defined (USE_DSOCKET)
	if (per_cpu(socket, cpu))
		sock_release(per_cpu(socket, cpu));

	pr_info("%s profile data socket released\n", current->comm);
#elif defined (USE_FILESYSTEM)
	if (per_cpu(trace_fd, cpu) >= 0) {
		kclose(per-cpu(trace_fd, cpu));
	}

	pr_info("%s profile data file closed\n", current->comm);
#endif
}

#ifdef CONFIG_LG_SYSPROF_KEVENT	/* kernel event log file */
void clean_kevent_data_container(int cpu, int *fd)
{
	int i = 0, ret = 0;
	char buf[256];
	mm_segment_t old_fs = get_fs();

	pr_info("write kernel event log file %d\n", kevent_cnt);
	set_fs(KERNEL_DS);
	for (i = 0; i < kevent_cnt; i++) {
		memset(buf, 0, 256);
		sprintf(buf, "%lld,%s,%s,%s\n", kevent_log[i].time, kevent_log[i].category, kevent_log[i].name, kevent_log[i].desc);
		ret = _kwrite(*fd, buf, strlen(buf));
		if (ret < 0)
			pr_err("kevent write error(%d)\n", ret);
	}
	kevent_cnt = 0;
#if defined (USE_NETWORK) || defined (USE_DSOCKET)
	if (kevt_socket)
		sock_release(kevt_socket);
	kevt_socket = NULL;
	pr_info("%s kevent socket released\n", current->comm);
#elif defined (USE_FILESYSTEM)
	if (*fd >= 0)
		sys_close(*fd);
	*fd = -1;
	pr_info("%s kevent file closed\n", current->comm);
#endif
	set_fs(old_fs);
}
#endif

static int ksysprofd(void *data)
{
	int cpu = (int)data;
	int cur_rp, cur_wp, ret;
	signed long timeout = KSYSPROF_DEFAULT_TIMEOUT;
	struct task_struct *tsk = current;
	int show_flag = 0;
#ifdef CONFIG_LG_SYSPROF_KEVENT
	int kevt_fd = -1;
#endif

	ignore_signals(tsk);

//	pr_info("%s %d is started\n", current->comm, __LINE__);

	/* wait for profile start */
	pr_info("%s/%d is called and sleep now\n", __func__, cpu);

	set_current_state(TASK_INTERRUPTIBLE);
	schedule();
	set_current_state(TASK_RUNNING);
	pr_info("%s/%d is waked up\n", __func__, cpu);

	ret = prepare_prof_data_container(cpu);
	if (ret < 0) {
		pr_err("Can't establish data container\n");
		return -EFAULT;
	}
	#ifdef CONFIG_LG_SYSPROF_KEVENT	/* kernel event log file */
	if (cpu == 0) {
		ret = prepare_kevent_data_container(cpu, &kevt_fd);
		if (ret < 0) {
			pr_err("Can't establish kevent container\n");
			return -EFAULT;
		}
	}
	#endif

	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(timeout);
		set_current_state(TASK_RUNNING);

		if (timeout == MAX_SCHEDULE_TIMEOUT) {
			pr_info("%s %d : cpu[%d:%p] wakeup to restart task tracing\n", __func__, __LINE__, cpu, current);
			show_flag = 1;
			ret = prepare_prof_data_container(cpu);
			if (ret < 0) {
				pr_err("Can't establish data container\n");
			}
			#ifdef CONFIG_LG_SYSPROF_KEVENT	/* kernel event log file */
			if (cpu == 0) {
				ret = prepare_kevent_data_container(cpu, &kevt_fd);
				if (ret < 0) {
					pr_err("Can't establish kevent container\n");
					return -EFAULT;
				}
			}
			#endif
		} else {
			show_flag = 0;
		}

		timeout = KSYSPROF_DEFAULT_TIMEOUT;
		/* wait until profile flag is on or cpu is on */
		if (check_current_position(cpu, &cur_rp, &cur_wp)) {
			if ((task_trace_flag == 0) || (cpu_is_offline(cpu))) {
				timeout = MAX_SCHEDULE_TIMEOUT;
//				#ifdef CONFIG_SYSPROF_DEBUG
				if (task_trace_flag == 0)
					pr_info("%s %d : cpu[%d] SEND all data in buffer to Server, cur_rp %d, cur_wp %d\n", __func__, __LINE__, cpu, cur_rp, cur_wp);
				if (cpu_is_offline(cpu))
					pr_info("%s %d : %s goto sleep owing to cpu[%d] turned off\n", __func__, __LINE__, current->comm, cpu);
//				#endif

				clean_prof_data_container(cpu);
				#ifdef CONFIG_LG_SYSPROF_KEVENT	/* kernel event log file */
				if (cpu == 0 && (kevt_fd >= 0)) {
					clean_kevent_data_container(cpu, &kevt_fd);
				}
				#endif
				pr_info("cpu %d stop_wait %d\n", cpu, stop_wait);
				if (cpu == 0 && stop_wait == 1) {
					trace_done_wakeup();
				}
			}
		}

//		pr_debug("debug cpu %d cur_rp %d cur_wp %d timemout %ld %s %d\n", cpu, cur_rp, cur_wp, timeout, current->comm, __LINE__);
		if (likely(cur_rp != cur_wp)) {
			if (show_flag == 1) {
				pr_info("%s %d : cpu[%d] start send buffer cur_rp %d cur_wp %d\n", __func__, __LINE__, cpu, cur_rp, cur_wp);
			}
			write_log(cpu, per_cpu(trace_fd, cpu), cur_rp, cur_wp);
		}

		if (kthread_should_stop()) {
			break;
		}
	}
	return 0;
}


static int __cpuinit sysprof_callback(struct notifier_block *nb, unsigned long action, void *cpu)
{
	int hotcpu = (unsigned long)cpu;
	struct task_struct *p;

	switch (action) {
		case CPU_UP_PREPARE:
		case CPU_UP_PREPARE_FROZEN:
			if (per_cpu(sysprofd, hotcpu) != NULL) {
				pr_info("CPU_UP but "KSYSPROF_DAEMON" %d is already created\n", hotcpu);
				return NOTIFY_OK;
			}

			p = kthread_create(ksysprofd, cpu, KSYSPROF_DAEMON"/%d", hotcpu);
			if (IS_ERR(p)) {
				pr_err(KSYSPROF_DAEMON" for %i failed\n", hotcpu);
				return notifier_from_errno(PTR_ERR(p));
			}
			kthread_bind(p, hotcpu);
			per_cpu(sysprofd, hotcpu) = p;
			pr_info(KSYSPROF_DAEMON"/%d : kthread_create is called\n", hotcpu);
			break;

		case CPU_ONLINE:
		case CPU_ONLINE_FROZEN:
			wake_up_process(per_cpu(sysprofd, hotcpu));
			pr_info(KSYSPROF_DAEMON"/%d : wake_up_process is called\n", hotcpu);
			break;
#ifdef CONFIG_HOTPLUG_CPU
		case CPU_UP_CANCELED:
		case CPU_UP_CANCELED_FROZEN:
			if (!per_cpu(sysprofd, hotcpu))
				break;
			break;

		case CPU_DEAD:
		case CPU_DEAD_FROZEN:
			pr_info(KSYSPROF_DAEMON"/%d : cpu is dead\n", hotcpu);
			break;
#endif
	}
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata sysprof_cpu_nb = {
	.notifier_call = sysprof_callback,
};

static int __init ksysprof_daemon_init (void)
{
	void *cpu = (void *)(long)smp_processor_id();
	int err, i;

	for (i = 0; i < NR_CPUS; i++) {
		per_cpu(trace_fd, i) = -1;
	}

	err = sysprof_callback(&sysprof_cpu_nb, CPU_UP_PREPARE, cpu);
	BUG_ON(err == NOTIFY_BAD);
	sysprof_callback(&sysprof_cpu_nb, CPU_ONLINE, cpu);
	register_cpu_notifier(&sysprof_cpu_nb);
	return 0;
}

void wakeup_sysprofd(int cpu)
{
	struct task_struct *p = per_cpu(sysprofd, cpu);
	if (p) {
		wake_up_process(p);
		pr_info("waekup process "KSYSPROF_DAEMON"/%d:%p\n", cpu, p);
	}
}
EXPORT_SYMBOL(wakeup_sysprofd);

static void __exit ksysprof_daemon_exit (void)
{
	int i;
	struct task_struct *p;

	for (i = 0; i < NR_CPUS; i++) {
		p = per_cpu(sysprofd, i);
		if (p) {
			kthread_stop(p);
		}
	}
}

MODULE_LICENSE("GPL");
early_initcall(ksysprof_daemon_init);
