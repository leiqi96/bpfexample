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


#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
struct bpf_map_def SEC("maps") _name = { \
  .type = _type, \
  .key_size = sizeof(_key_type), \
  .value_size = sizeof(_value_type), \
  .max_entries = _max_entries, \
};

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries);

#define BPF_ARRAY(_name, _value_type, _max_entries) \
BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries);


BPF_ARRAY(path_buf, buf_t, 1);


// static __always_inline buf_t* get_buf(int idx)
// {
//     return bpf_map_lookup_elem(&bufs, &idx);
// }

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


static __always_inline int save_dentry_path_to_str_buf(struct dentry* dentry, char *buf, int buflen )
{
    char slash = '/';
    int zero = 0;

    char *end = buf + buflen;
    struct qstr dentry_name = get_d_name_from_dentry(dentry);
    unsigned int len = dentry_name.len;
    unsigned int off = buflen - len;
    if(off<0){
        return off;
    }
    char *start = end - len;
    bpf_probe_read(start,len,(void *)dentry_name.name);

    #pragma unroll
    // As bpf loops are not allowed and max instructions number is 4096, path components is limited to 30
    for (int i = 0; i < 29; i++) {
        struct dentry *d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == d_parent) {
            break;
        }
        // Add this dentry name to path
        struct qstr d_name = get_d_name_from_dentry(dentry);
        len = d_name.len;
        off = buflen - len - 1;
        // Is string buffer big enough for dentry name?
        if(off<0){
            break;
        }else{
            start = (start - 1);
            bpf_probe_read(start,1,&slash);
            start = start - len;
            bpf_probe_read(start,len,(void *)dentry_name.name);
        }
        dentry = d_parent;
    }

    bpf_probe_read(buf,buflen-off,start);

    return off;
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

    int fd = (int)ctx->args[0];
    if (fd == AT_FDCWD){
        bpf_probe_read_user_str(&process->fname, sizeof(process->fname), (const char *)ctx->args[1]);
    }else{
        int idx = 0;
        buf_t *string_p = bpf_map_lookup_elem(&path_buf, &idx);
        struct dentry *dentry_ptr = get_dentry_ptr_from_fd(task,fd);
        int off = save_dentry_path_to_str_buf(dentry_ptr,string_p->buf,NAME_MAX);
        if(off){
            char *start = string_p->buf + (NAME_MAX-off);   
            bpf_probe_read_user_str(start, off, (const char *)ctx->args[1]);
        }
        bpf_probe_read(&process->fname,NAME_MAX,string_p->buf);
    }
    process->mode = (int)ctx->args[2];
    
    bpf_ringbuf_submit(process, ringbuffer_flags);
    return 0;
}


char LICENSE[] SEC("license") = "GPL";