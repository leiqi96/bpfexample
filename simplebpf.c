#include "vmlinux.h"
#include <bpf/bpf_helpers.h> 
#include "simple.h"


typedef struct context {
    u32 pid_ns;
    u32 pid;
    umode_t mode;
    char comm[TASK_COMM_LEN];
    const char *fname;  
} context_t;


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

// static __always_inline struct path get_path_from_file(struct file *file)
// {
//     return READ_KERN(file->f_path);
// }

// static __always_inline struct file get_file_from_fd(struct task_struct *task,unsigned int fd)
// {
//     struct file *file = READ_KERN(READ_KERN(READ_KERN(task->files)->fdt)->fd)
//     return file[fd];
// }


SEC("tracepoint/syscalls/sys_enter_chmod")
int tracepoint__syscalls__sys_enter_chmod(struct trace_event_raw_sys_enter* ctx){    
    u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid_ns = get_task_pid_ns_id(task);
    context_t *context;
    context = bpf_ringbuf_reserve(&events, sizeof(context_t), ringbuffer_flags);
    if (!context) {
        return 0;
    }

    context->pid_ns = pid_ns;
    context->pid = pid;
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    context->fname = (const char *)ctx->args[0]
    context->mode = (umode_t)ctx->args[1]
    
    bpf_ringbuf_submit(context, ringbuffer_flags);

    return 0;
}


// SEC("tracepoint/syscalls/sys_enter_fchmod")
// int tracepoint__syscalls__sys_enter_fchmod(struct trace_event_raw_sys_enter* ctx){
//     u64 id = bpf_get_current_pid_tgid();
// 	u32 pid = id >> 32;
    
//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     u32 pid_ns = get_task_pid_ns_id(task);
//     context_t *context;
//     context = bpf_ringbuf_reserve(&events, sizeof(context_t), ringbuffer_flags);
//     if (!context) {
//         return 0;
//     }

//     context->pid_ns = pid_ns;
//     context->pid = pid;
//     bpf_get_current_comm(&context->comm, sizeof(context->comm));
    
//     context->fname = 
//     context->mode = (umode_t)ctx->args[1]
    
//     bpf_ringbuf_submit(context, ringbuffer_flags);

//     return 0;
// }


// SEC("tracepoint/syscalls/sys_enter_fchmodat")
// int tracepoint__syscalls__sys_enter_fchmodat(struct trace_event_raw_sys_enter* ctx){
    
// }