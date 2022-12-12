#include "vmlinux.h"
#include <bpf/bpf_helpers.h> 

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define MAX_PERCPU_BUFSIZE  255     // This value is actually set by the kernel as an upper bound
#define STRING_BUF_IDX      1
#define MAX_BUFFERS         2
#define AT_FDCWD             -100

typedef struct process_info {
    u32 pid_ns;
    u32 pid;
    int mode;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX]; 
} proc_info;

typedef struct simple_buf {
    char buf[NAME_MAX];
} buf_t;


#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries, _pinning)     \
    struct {                                                            \
        __uint(type, _type);                                            \
        __uint(max_entries, _max_entries);                              \
        __type(key, _key_type);                                         \
        __type(value, _value_type);                                     \
        __uint(pinning, _pinning);                                      \
    } _name SEC(".maps");                                               

#define MAP_RINGBUF(_name, _max_entries, _pinning)                     \
    struct {                                                           \
        __uint(type, BPF_MAP_TYPE_RINGBUF);                            \
        __uint(max_entries, _max_entries);                             \
        __uint(pinning, _pinning);                                     \
    } _name SEC(".maps");

#define MAP_PERCPU_ARRAY(_name, _value_type, _max_entries, _pinning) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries, _pinning)

#define MAP_ARRAY(_name, _value_type, _max_entries, _pinning) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries, _pinning)



MAP_ARRAY(path_buf, buf_t, 1, 0);


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
    unsigned int level = 0;
    struct pid *pid = NULL;
    struct pid_namespace *ns = NULL;
    pid = READ_KERN(task->thread_pid);
    level = READ_KERN(pid->level);
    ns = READ_KERN(pid->numbers[level].ns);
    return READ_KERN(ns->ns.inum);
}

static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_name);
}

static __always_inline struct dentry* get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_parent);
}

static __always_inline struct dentry* get_dentry_ptr_from_fd(struct task_struct *task,int fd){
    struct file ** file_array = READ_KERN(READ_KERN(task->files)->fd_array);
    struct path f_path  = READ_KERN(file_array[fd]->f_path);
    return READ_KERN(f_path.dentry);
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