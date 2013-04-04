var seccomp = require('./build/Release/seccomp_filter');

console.log( 'Seccomp GO!' );


var all_calls = [
	"read",
	"write",
	"open",
	"close",
	"stat",
	"fstat",
	"lstat",
	"poll",
	"lseek",
	"mmap",
	"mprotect",
	"munmap",
	"brk",
	"rt_sigaction",
	"rt_sigprocmask",
	"rt_sigreturn",
	"ioctl",
	"pread64",
	"pwrite64",
	"readv",
	"writev",
	"access",
	"pipe",
	"select",
	"sched_yield",
	"mremap",
	"msync",
	"mincore",
	"madvise",
	"shmget",
	"shmat",
	"shmctl",
	"dup",
	"dup2",
	"pause",
	"nanosleep",
	"getitimer",
	"alarm",
	"setitimer",
	"getpid",
	"sendfile",
	"socket",
	"connect",
	"accept",
	"sendto",
	"recvfrom",
	"sendmsg",
	"recvmsg",
	"shutdown",
	"bind",
	"listen",
	"getsockname",
	"getpeername",
	"socketpair",
	"setsockopt",
	"getsockopt",
	"clone",
	"fork",
	"vfork",
	"execve",
	"exit",
	"wait4",
	"kill",
	"uname",
	"semget",
	"semop",
	"semctl",
	"shmdt",
	"msgget",
	"msgsnd",
	"msgrcv",
	"msgctl",
	"fcntl",
	"flock",
	"fsync",
	"fdatasync",
	"truncate",
	"ftruncate",
	"getdents",
	"getcwd",
	"chdir",
	"fchdir",
	"rename",
	"mkdir",
	"rmdir",
	"creat",
	"link",
	"unlink",
	"symlink",
	"readlink",
	"chmod",
	"fchmod",
	"chown",
	"fchown",
	"lchown",
	"umask",
	"gettimeofday",
	"getrlimit",
	"getrusage",
	"sysinfo",
	"times",
	"ptrace",
	"getuid",
	"syslog",
	"getgid",
	"setuid",
	"setgid",
	"geteuid",
	"getegid",
	"setpgid",
	"getppid",
	"getpgrp",
	"setsid",
	"setreuid",
	"setregid",
	"getgroups",
	"setgroups",
	"setresuid",
	"getresuid",
	"setresgid",
	"getresgid",
	"getpgid",
	"setfsuid",
	"setfsgid",
	"getsid",
	"capget",
	"capset",
	"rt_sigpending",
	"rt_sigtimedwait",
	"rt_sigqueueinfo",
	"rt_sigsuspend",
	"sigaltstack",
	"utime",
	"mknod",
	"uselib",
	"personality",
	"ustat",
	"statfs",
	"fstatfs",
	"sysfs",
	"getpriority",
	"setpriority",
	"sched_setparam",
	"sched_getparam",
	"sched_setscheduler",
	"sched_getscheduler",
	"sched_get_priority_max",
	"sched_get_priority_min",
	"sched_rr_get_interval",
	"mlock",
	"munlock",
	"mlockall",
	"munlockall",
	"vhangup",
	"modify_ldt",
	"pivot_root",
	"_sysctl",
	"prctl",
	"arch_prctl",
	"adjtimex",
	"setrlimit",
	"chroot",
	"sync",
	"acct",
	"settimeofday",
	"mount",
	"umount2",
	"swapon",
	"swapoff",
	"reboot",
	"sethostname",
	"setdomainname",
	"iopl",
	"ioperm",
	"create_module",
	"init_module",
	"delete_module",
	"get_kernel_syms",
	"query_module",
	"quotactl",
	"nfsservctl",
	"getpmsg",
	"putpmsg",
	"afs_syscall",
	"tuxcall",
	"security",
	"gettid",
	"readahead",
	"setxattr",
	"lsetxattr",
	"fsetxattr",
	"getxattr",
	"lgetxattr",
	"fgetxattr",
	"listxattr",
	"llistxattr",
	"flistxattr",
	"removexattr",
	"lremovexattr",
	"fremovexattr",
	"tkill",
	"time",
	"futex",
	"sched_setaffinity",
	"sched_getaffinity",
	"set_thread_area",
	"io_setup",
	"io_destroy",
	"io_getevents",
	"io_submit",
	"io_cancel",
	"get_thread_area",
	"lookup_dcookie",
	"epoll_create",
	"epoll_ctl_old",
	"epoll_wait_old",
	"remap_file_pages",
	"getdents64",
	"set_tid_address",
	"restart_syscall",
	"semtimedop",
	"fadvise64",
	"timer_create",
	"timer_settime",
	"timer_gettime",
	"timer_getoverrun",
	"timer_delete",
	"clock_settime",
	"clock_gettime",
	"clock_getres",
	"clock_nanosleep",
	"exit_group",
	"epoll_wait",
	"epoll_ctl",
	"tgkill",
	"utimes",
	"vserver",
	"mbind",
	"set_mempolicy",
	"get_mempolicy",
	"mq_open",
	"mq_unlink",
	"mq_timedsend",
	"mq_timedreceive",
	"mq_notify",
	"mq_getsetattr",
	"kexec_load",
	"waitid",
	"add_key",
	"request_key",
	"keyctl",
	"ioprio_set",
	"ioprio_get",
	"inotify_init",
	"inotify_add_watch",
	"inotify_rm_watch",
	"migrate_pages",
	"openat",
	"mkdirat",
	"mknodat",
	"fchownat",
	"futimesat",
	"newfstatat",
	"unlinkat",
	"renameat",
	"linkat",
	"symlinkat",
	"readlinkat",
	"fchmodat",
	"faccessat",
	"pselect6",
	"ppoll",
	"unshare",
	"set_robust_list",
	"get_robust_list",
	"splice",
	"tee",
	"sync_file_range",
	"vmsplice",
	"move_pages",
	"utimensat",
	"epoll_pwait",
	"signalfd",
	"timerfd_create",
	"eventfd",
	"fallocate",
	"timerfd_settime",
	"timerfd_gettime",
	"accept4",
	"signalfd4",
	"eventfd2",
	"epoll_create1",
	"dup3",
	"pipe2",
	"inotify_init1",
	"preadv",
	"pwritev",
	"rt_tgsigqueueinfo",
	"perf_event_open",
	"recvmmsg",
	"fanotify_init",
	"fanotify_mark",
	"prlimit64",
	"name_to_handle_at",
	"open_by_handle_at",
	"clock_adjtime",
	"syncfs",
	"sendmmsg",
	"setns",
	"getcpu",
	"process_vm_readv",
	"process_vm_writev",
	"kcmp",
];

var node_calls = [
	"accept",
	"accept4",
	"access",
	"acct",
	"add_key",
	"adjtimex",
	"afs_syscall",
	"alarm",
	"arch_prctl",
	"bind",
	"brk",
	"capget",
	"capset",
	"chdir",
	"chmod",
	"chown",
	"chroot",
	"close",
	"connect",
	"creat",
	"create_module",
	"delete_module",
	"dup",
	"dup2",
	"dup3",
	"epoll_create",
	"epoll_create1",
	"epoll_ctl",
	"epoll_ctl_old",
	"epoll_pwait",
	"epoll_wait",
	"epoll_wait_old",
	"eventfd",
	"eventfd2",
	"execve",
	"exit",
	"exit_group",
	"faccessat",
	"fadvise64",
	"fallocate",
	"fanotify_init",
	"fanotify_mark",
	"fchdir",
	"fchmod",
	"fchmodat",
	"fchown",
	"fchownat",
	"fcntl",
	"fdatasync",
	"fgetxattr",
	"flistxattr",
	"flock",
	"fork",
	"fremovexattr",
	"fsetxattr",
	"fstat",
	"fstatfs",
	"fsync",
	"ftruncate",
	"futex",
	"futimesat",
	"getcpu",
	"getcwd",
	"getdents",
	"getdents64",
	"getegid",
	"geteuid",
	"getgid",
	"getgroups",
	"getitimer",
	"get_kernel_syms",
	"get_mempolicy",
	"getpeername",
	"getpgid",
	"getpgrp",
	"getpid",
	"getpmsg",
	"getppid",
	"getpriority",
	"getresgid",
	"getresuid",
	"getrlimit",
	"get_robust_list",
	"getrusage",
	"getsid",
	"getsockname",
	"getsockopt",
	"get_thread_area",
	"gettid",
	"gettimeofday",
	"getuid",
	"getxattr",
	"init_module",
	"inotify_add_watch",
	"inotify_init",
	"inotify_init1",
	"inotify_rm_watch",
	"io_cancel",
	"ioctl",
	"io_destroy",
	"io_getevents",
	"ioperm",
	"iopl",
	"ioprio_get",
	"ioprio_set",
	"io_setup",
	"io_submit",
	"kcmp",
	"kexec_load",
	"keyctl",
	"kill",
	"lchown",
	"lgetxattr",
	"link",
	"linkat",
	"listen",
	"listxattr",
	"llistxattr",
	"lookup_dcookie",
	"lremovexattr",
	"lseek",
	"lsetxattr",
	"lstat",
	"madvise",
	"mbind",
	"migrate_pages",
	"mincore",
	"mkdir",
	"mkdirat",
	"mknod",
	"mknodat",
	"mlock",
	"mlockall",
	"mmap",
	"modify_ldt",
	"mount",
	"move_pages",
	"mprotect",
	"mq_getsetattr",
	"mq_notify",
	"mq_open",
	"mq_timedreceive",
	"mq_timedsend",
	"mq_unlink",
	"mremap",
	"msgctl",
	"msgget",
	"msgrcv",
	"msgsnd",
	"msync",
	"munlock",
	"munlockall",
	"munmap",
	"name_to_handle_at",
	"nanosleep",
	"newfstatat",
	"nfsservctl",
	"pause",
	"personality",
	"pipe",
	"pipe2",
	"pivot_root",
	"poll",
	"ppoll",
	"prctl",
	"pread64",
	"preadv",
	"prlimit64",
	"process_vm_readv",
	"process_vm_writev",
	"pselect6",
	"ptrace",
	"putpmsg",
	"pwrite64",
	"pwritev",
	"query_module",
	"quotactl",
	"read",
	"readahead",
	"readlink",
	"readlinkat",
	"readv",
	"reboot",
	"recvfrom",
	"recvmmsg",
	"recvmsg",
	"remap_file_pages",
	"removexattr",
	"rename",
	"renameat",
	"request_key",
	"restart_syscall",
	"rmdir",
	"rt_sigaction",
	"rt_sigpending",
	"rt_sigprocmask",
	"rt_sigqueueinfo",
	"rt_sigreturn",
	"rt_sigsuspend",
	"rt_sigtimedwait",
	"rt_tgsigqueueinfo",
	"sched_getaffinity",
	"sched_getparam",
	"sched_get_priority_max",
	"sched_get_priority_min",
	"sched_getscheduler",
	"sched_rr_get_interval",
	"sched_setaffinity",
	"sched_setparam",
	"sched_setscheduler",
	"sched_yield",
	"security",
	"select",
	"semctl",
	"semget",
	"semop",
	"semtimedop",
	"sendfile",
	"sendmmsg",
	"sendmsg",
	"sendto",
	"setdomainname",
	"setfsgid",
	"write",
];
var minimal_calls = ["read", "write", "exit", "rt_sigreturn"];

var fs = require("fs");

seccomp.enter({
	allowed_calls: node_calls,
	// default_action: "allow"
});

console.log( 'Seccomp DONE!' );
console.log(fs.readFileSync("/tmp/startup-actions-tim.log"));
