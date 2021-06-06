#include <linux/types.h>
#include <bpf_helpers.h>


typedef struct context {
    u32 pid_ns;
    u32 pid;
    char comm[TASK_COMM_LEN];
} context_t;


SYSCALL_DEFINE3(fchmodat, int, dfd, const char __user *, filename,
		umode_t, mode)
{
	return do_fchmodat(dfd, filename, mode);
}

SYSCALL_DEFINE2(chmod, const char __user *, filename, umode_t, mode)
{
	return do_fchmodat(AT_FDCWD, filename, mode);
}

SYSCALL_DEFINE2(fchmod, unsigned int, fd, umode_t, mode)
{
	return ksys_fchmod(fd, mode);
}