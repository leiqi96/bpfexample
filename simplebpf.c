#include "vmlinux.h"
#include <bpf/bpf_helpers.h> 

#define TASK_COMM_LEN 16
#define NAME_MAX 255

typedef struct process_info {
    u32 pid_ns;
    u32 pid;
    int mode;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX]; 
} proc_info;


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

long ringbuffer_flags = 0;

#define READ_KERN(ptr) ({ typeof(ptr) _val;                             \
                          __builtin_memset(&_val, 0, sizeof(_val));     \
                          bpf_probe_read(&_val, sizeof(_val), &ptr);    \
                          _val;                                         \
                        })

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->pid_ns_for_children)->ns.inum);
}


SEC("tracepoint/syscalls/sys_enter_chmod")
int tracepoint__syscalls__sys_enter_chmod(struct trace_event_raw_sys_enter* ctx){    
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid_ns = get_task_pid_ns_id(task);
    proc_info *process;
    process = bpf_ringbuf_reserve(&events, sizeof(proc_info), ringbuffer_flags);
    if (!process) {
        return 0;
    }

    process->pid_ns = pid_ns;
    process->pid = pid;
    bpf_get_current_comm(&process->comm, sizeof(process->comm));

    bpf_probe_read_user_str(&process->fname, sizeof(process->fname), (const char *)ctx->args[0]);
    process->mode = (int)ctx->args[1];
    
    bpf_ringbuf_submit(process, ringbuffer_flags);

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tracepoint__syscalls__sys_enter_fchmodat(struct trace_event_raw_sys_enter* ctx){    
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid_ns = get_task_pid_ns_id(task);
    proc_info *process;
    process = bpf_ringbuf_reserve(&events, sizeof(proc_info), ringbuffer_flags);
    if (!process) {
        return 0;
    }

    process->pid_ns = pid_ns;
    process->pid = pid;
    bpf_get_current_comm(&process->comm, sizeof(process->comm));

    bpf_probe_read_user_str(&process->fname, sizeof(process->fname), (const char *)ctx->args[1]);
    process->mode = (int)ctx->args[2];
    
    bpf_ringbuf_submit(process, ringbuffer_flags);

    return 0;
}


char LICENSE[] SEC("license") = "GPL";