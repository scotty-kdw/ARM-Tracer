#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <assert.h>
#include <dirent.h>
//#include "darm.h"
#include <inttypes.h>
#include "capstone.h"

typedef unsigned long	CORE_ADDR;
typedef unsigned long	ULONGEST;

/* Set to true if the 32-bit mode is in use.  */
static int arm_apcs_32 = 1;

//static const unsigned long arm_breakpoint = 0xef9f0001;
//static const unsigned long thumb_breakpoint = 0x01de;

//static const unsigned long arm_breakpoint = 0xe727ff7f;
//static const unsigned long thumb_breakpoint = 0x00be;

static const unsigned long arm_breakpoint = 0xe7f001f0;
static const unsigned long thumb_breakpoint = 0x01de;

static const unsigned long thumb2_breakpoint[] = { 0xf7f0, 0xa000 };

static char signal_name[64][64] = {
	"EXIT",
	"SIGHUP /* Hangup (POSIX).  */",
	"SIGINT /* Interrupt (ANSI).  */",
	"SIGQUIT /* Quit (POSIX).  */",
	"SIGILL /* Illegal instruction (ANSI).  */",
	"SIGTRAP /* Trace trap (POSIX).  */",
	"SIGABRT /* Abort (ANSI).  */",
	"SIGBUS /* BUS error (4.2 BSD).  */",
	"SIGFPE /* Floating-point exception (ANSI).  */",
	"SIGKILL /* Kill, unblockable (POSIX).  */",
	"SIGUSR1 /* User-defined 1 SIGnal (POSIX).  */",
	"SIGSEGV /* Segmentation violation (ANSI).  */",
	"SIGUSR2 /* User-defined 2 SIGnal (POSIX).  */",
	"SIGPIPE /* Broken pipe (POSIX).  */",
	"SIGALRM /* Alarm clock (POSIX).  */",
	"SIGTERM /* Termination (ANSI).  */",
	"SIGSTKFLT /* Stack fault.  */",
	"SIGCHLD /* Child status has changed (POSIX).  */",
	"SIGCONT /* Continue (POSIX).  */",
	"SIGSTOP /* Stop, unblockable (POSIX).  */",
	"SIGTSTP /* Keyboard stop (POSIX).  */",
	"SIGTTIN /* Background read from tty (POSIX).  */",
	"SIGTTOU /* Background write to tty (POSIX).  */",
	"SIGURG /* Urgent condition on socket (4.2 BSD).  */",
	"SIGXCPU /* CPU limit exceeded (4.2 BSD).  */",
	"SIGXFSZ /* File size limit exceeded (4.2 BSD).  */",
	"SIGVTALRM /* Virtual alarm clock (4.2 BSD).  */",
	"SIGPROF /* Profiling alarm clock (4.2 BSD).  */",
	"SIGWINCH /* Window size change (4.3 BSD, Sun).  */",
	"SIGIO /* I/O now possible (4.2 BSD).  */",
	"SIGPWR /* Power failure restart (System V).  */",
	"SIGSYS /* Bad system call.  */"
};

static char svc_call_name[512][64] = {
	"sys_restart_syscall",
	"sys_exit",
	"sys_fork_wrapper",
	"sys_read",
	"sys_write",
	"sys_open",
	"sys_close",
	"sys_ni_syscall	/* was sys_waitpid */",
	"sys_creat",
	"sys_link",
	"sys_unlink",
	"sys_execve_wrapper",
	"sys_chdir",
	"sys_time	/* used by libc4 */",
	"sys_mknod",
	"sys_chmod",
	"sys_lchown16",
	"sys_ni_syscall	/* was sys_break */",
	"sys_ni_syscall	/* was sys_stat */",
	"sys_lseek",
	"sys_getpid",
	"sys_mount",
	"sys_oldumount	/* used by libc4 */",
	"sys_setuid16",
	"sys_getuid16",
	"sys_stime",
	"sys_ptrace",
	"sys_alarm	/* used by libc4 */",
	"sys_ni_syscall	/* was sys_fstat */",
	"sys_pause",
	"sys_utime	/* used by libc4 */",
	"sys_ni_syscall	/* was sys_stty */",
	"sys_ni_syscall	/* was sys_getty */",
	"sys_access",
	"sys_nice",
	"sys_ni_syscall	/* was sys_ftime */",
	"sys_sync",
	"sys_kill",
	"sys_rename",
	"sys_mkdir",
	"sys_rmdir",
	"sys_dup",
	"sys_pipe",
	"sys_times",
	"sys_ni_syscall	/* was sys_prof */",
	"sys_brk",
	"sys_setgid16",
	"sys_getgid16",
	"sys_ni_syscall	/* was sys_signal */",
	"sys_geteuid16",
	"sys_getegid16",
	"sys_acct",
	"sys_umount",
	"sys_ni_syscall	/* was sys_lock */",
	"sys_ioctl",
	"sys_fcntl",
	"sys_ni_syscall	/* was sys_mpx */",
	"sys_setpgid",
	"sys_ni_syscall	/* was sys_ulimit */",
	"sys_ni_syscall	/* was sys_olduname */",
	"sys_umask",
	"sys_chroot",
	"sys_ustat",
	"sys_dup2",
	"sys_getppid",
	"sys_getpgrp",
	"sys_setsid",
	"sys_sigaction",
	"sys_ni_syscall	/* was sys_sgetmask */",
	"sys_ni_syscall	/* was sys_ssetmask */",
	"sys_setreuid16",
	"sys_setregid16",
	"sys_sigsuspend",
	"sys_sigpending",
	"sys_sethostname",
	"sys_setrlimit",
	"sys_old_getrlimit 	/* used by libc4 */",
	"sys_getrusage",
	"sys_gettimeofday",
	"sys_settimeofday",
	"sys_getgroups16",
	"sys_setgroups16",
	"sys_old_select	/* used by libc4 */",
	"sys_symlink",
	"sys_ni_syscall	/* was sys_lstat */",
	"sys_readlink",
	"sys_uselib",
	"sys_swapon",
	"sys_reboot",
	"sys_old_readdir	/* used by libc4 */",
	"sys_old_mmap	/* used by libc4 */",
	"sys_munmap",
	"sys_truncate",
	"sys_ftruncate",
	"sys_fchmod",
	"sys_fchown16",
	"sys_getpriority",
	"sys_setpriority",
	"sys_ni_syscall	/* was sys_profil */",
	"sys_statfs",
	"sys_fstatfs",
	"sys_ni_syscall	/* sys_ioperm */",
	"sys_socketcall, sys_oabi_socketcall",
	"sys_syslog",
	"sys_setitimer",
	"sys_getitimer",
	"sys_newstat",
	"sys_newlstat",
	"sys_newfstat",
	"sys_ni_syscall	/* was sys_uname */",
	"sys_ni_syscall	/* was sys_iopl */",
	"sys_vhangup",
	"sys_ni_syscall",
	"sys_syscall	/* call a syscall */",
	"sys_wait4",
	"sys_swapoff",
	"sys_sysinfo",
	"sys_ipc, sys_oabi_ipc",
	"sys_fsync",
	"sys_sigreturn_wrapper",
	"sys_clone_wrapper",
	"sys_setdomainname",
	"sys_newuname",
	"sys_ni_syscall	/* modify_ldt */",
	"sys_adjtimex",
	"sys_mprotect",
	"sys_sigprocmask",
	"sys_ni_syscall	/* was sys_create_module */",
	"sys_init_module",
	"sys_delete_module",
	"sys_ni_syscall	/* was sys_get_kernel_syms */",
	"sys_quotactl",
	"sys_getpgid",
	"sys_fchdir",
	"sys_bdflush",
	"sys_sysfs",
	"sys_personality",
	"sys_ni_syscall	/* reserved for afs_syscall */",
	"sys_setfsuid16",
	"sys_setfsgid16",
	"sys_llseek",
	"sys_getdents",
	"sys_select",
	"sys_flock",
	"sys_msync",
	"sys_readv",
	"sys_writev",
	"sys_getsid",
	"sys_fdatasync",
	"sys_sysctl",
	"sys_mlock",
	"sys_munlock",
	"sys_mlockall",
	"sys_munlockall",
	"sys_sched_setparam",
	"sys_sched_getparam",
	"sys_sched_setscheduler",
	"sys_sched_getscheduler",
	"sys_sched_yield",
	"sys_sched_get_priority_max",
	"sys_sched_get_priority_min",
	"sys_sched_rr_get_interval",
	"sys_nanosleep",
	"sys_mremap",
	"sys_setresuid16",
	"sys_getresuid16",
	"sys_ni_syscall	/* vm86 */",
	"sys_ni_syscall	/* was sys_query_module */",
	"sys_poll",
	"sys_nfsservctl",
	"sys_setresgid16",
	"sys_getresgid16",
	"sys_prctl",
	"sys_rt_sigreturn_wrapper",
	"sys_rt_sigaction",
	"sys_rt_sigprocmask",
	"sys_rt_sigpending",
	"sys_rt_sigtimedwait",
	"sys_rt_sigqueueinfo",
	"sys_rt_sigsuspend",
	"sys_pread64, sys_oabi_pread64",
	"sys_pwrite64, sys_oabi_pwrite64",
	"sys_chown16",
	"sys_getcwd",
	"sys_capget",
	"sys_capset",
	"sys_sigaltstack_wrapper",
	"sys_sendfile",
	"sys_ni_syscall	/* getpmsg */",
	"sys_ni_syscall	/* putpmsg */",
	"sys_vfork_wrapper",
	"sys_getrlimit",
	"sys_mmap2",
	"sys_truncate64, sys_oabi_truncate64",
	"sys_ftruncate64, sys_oabi_ftruncate64",
	"sys_stat64, sys_oabi_stat64",
	"sys_lstat64, sys_oabi_lstat64",
	"sys_fstat64, sys_oabi_fstat64",
	"sys_lchown",
	"sys_getuid",
	"sys_getgid",
	"sys_geteuid",
	"sys_getegid",
	"sys_setreuid",
	"sys_setregid",
	"sys_getgroups",
	"sys_setgroups",
	"sys_fchown",
	"sys_setresuid",
	"sys_getresuid",
	"sys_setresgid",
	"sys_getresgid",
	"sys_chown",
	"sys_setuid",
	"sys_setgid",
	"sys_setfsuid",
	"sys_setfsgid",
	"sys_getdents64",
	"sys_pivot_root",
	"sys_mincore",
	"sys_madvise",
	"sys_fcntl64, sys_oabi_fcntl64",
	"sys_ni_syscall 	/* TUX */",
	"sys_ni_syscall",
	"sys_gettid",
	"sys_readahead, sys_oabi_readahead",
	"sys_setxattr",
	"sys_lsetxattr",
	"sys_fsetxattr",
	"sys_getxattr",
	"sys_lgetxattr",
	"sys_fgetxattr",
	"sys_listxattr",
	"sys_llistxattr",
	"sys_flistxattr",
	"sys_removexattr",
	"sys_lremovexattr",
	"sys_fremovexattr",
	"sys_tkill",
	"sys_sendfile64",
	"sys_futex",
	"sys_sched_setaffinity",
	"sys_sched_getaffinity",
	"sys_io_setup",
	"sys_io_destroy",
	"sys_io_getevents",
	"sys_io_submit",
	"sys_io_cancel",
	"sys_exit_group",
	"sys_lookup_dcookie",
	"sys_epoll_create",
	"sys_epoll_ctl, sys_oabi_epoll_ctl",
	"sys_epoll_wait, sys_oabi_epoll_wait",
	"sys_remap_file_pages",
	"sys_ni_syscall	/* sys_set_thread_area */",
	"sys_ni_syscall	/* sys_get_thread_area */",
	"sys_set_tid_address",
	"sys_timer_create",
	"sys_timer_settime",
	"sys_timer_gettime",
	"sys_timer_getoverrun",
	"sys_timer_delete",
	"sys_clock_settime",
	"sys_clock_gettime",
	"sys_clock_getres",
	"sys_clock_nanosleep",
	"sys_statfs64_wrapper",
	"sys_fstatfs64_wrapper",
	"sys_tgkill",
	"sys_utimes",
	"sys_arm_fadvise64_64",
	"sys_pciconfig_iobase",
	"sys_pciconfig_read",
	"sys_pciconfig_write",
	"sys_mq_open",
	"sys_mq_unlink",
	"sys_mq_timedsend",
	"sys_mq_timedreceive",
	"sys_mq_notify",
	"sys_mq_getsetattr",
	"sys_waitid",
	"sys_socket",
	"sys_bind, sys_oabi_bind",
	"sys_connect, sys_oabi_connect",
	"sys_listen",
	"sys_accept",
	"sys_getsockname",
	"sys_getpeername",
	"sys_socketpair",
	"sys_send",
	"sys_sendto, sys_oabi_sendto",
	"sys_recv",
	"sys_recvfrom",
	"sys_shutdown",
	"sys_setsockopt",
	"sys_getsockopt",
	"sys_sendmsg, sys_oabi_sendmsg",
	"sys_recvmsg",
	"sys_semop, sys_oabi_semop",
	"sys_semget",
	"sys_semctl",
	"sys_msgsnd",
	"sys_msgrcv",
	"sys_msgget",
	"sys_msgctl",
	"sys_shmat",
	"sys_shmdt",
	"sys_shmget",
	"sys_shmctl",
	"sys_add_key",
	"sys_request_key",
	"sys_keyctl",
	"sys_semtimedop, sys_oabi_semtimedop",
	"sys_ni_syscall",
	"sys_ioprio_set",
	"sys_ioprio_get",
	"sys_inotify_init",
	"sys_inotify_add_watch",
	"sys_inotify_rm_watch",
	"sys_mbind",
	"sys_get_mempolicy",
	"sys_set_mempolicy",
	"sys_openat",
	"sys_mkdirat",
	"sys_mknodat",
	"sys_fchownat",
	"sys_futimesat",
	"sys_fstatat64,  sys_oabi_fstatat64",
	"sys_unlinkat",
	"sys_renameat",
	"sys_linkat",
	"sys_symlinkat",
	"sys_readlinkat",
	"sys_fchmodat",
	"sys_faccessat",
	"sys_pselect6",
	"sys_ppoll",
	"sys_unshare",
	"sys_set_robust_list",
	"sys_get_robust_list",
	"sys_splice",
	"sys_sync_file_range2",
	"sys_tee",
	"sys_vmsplice",
	"sys_move_pages",
	"sys_getcpu",
	"sys_epoll_pwait",
	"sys_kexec_load",
	"sys_utimensat",
	"sys_signalfd",
	"sys_timerfd_create",
	"sys_eventfd",
	"sys_fallocate",
	"sys_timerfd_settime",
	"sys_timerfd_gettime",
	"sys_signalfd4",
	"sys_eventfd2",
	"sys_epoll_create1",
	"sys_dup3",
	"sys_pipe2",
	"sys_inotify_init1",
	"sys_preadv",
	"sys_pwritev",
	"sys_rt_tgsigqueueinfo",
	"sys_perf_event_open",
	"sys_recvmmsg",
	"sys_accept4",
	"sys_fanotify_init",
	"sys_fanotify_mark",
	"sys_prlimit64"
};


typedef union {
	unsigned long instrs;
	unsigned char instr[4];
} Instruction;

typedef struct {
	char			map_name[128];
	unsigned long	map_start_addr;
	unsigned long	map_end_addr;
} mapdump_t;

typedef struct {
	unsigned long uregs[18];
} arm_regs;

#define ARM_cpsr        uregs[16]
#define ARM_pc          uregs[15]
#define ARM_lr          uregs[14]
#define ARM_sp          uregs[13]
#define ARM_r12         uregs[12]
#define ARM_r11         uregs[11]
#define ARM_r10         uregs[10]
#define ARM_r9          uregs[9]
#define ARM_r8          uregs[8]
#define ARM_r7          uregs[7]
#define ARM_r6          uregs[6]
#define ARM_r5          uregs[5]
#define ARM_r4          uregs[4]
#define ARM_r3          uregs[3]
#define ARM_r2          uregs[2]
#define ARM_r1          uregs[1]
#define ARM_r0          uregs[0]
#define ARM_ORIG_r0     uregs[17]


enum gdb_regnum {
  ARM_A1_REGNUM = 0,        /* first integer-like argument */
  ARM_A4_REGNUM = 3,        /* last integer-like argument */
  ARM_AP_REGNUM = 11,
  ARM_IP_REGNUM = 12,
  ARM_SP_REGNUM = 13,       /* Contains address of top of stack */
  ARM_LR_REGNUM = 14,       /* address to return to from a function call */
  ARM_PC_REGNUM = 15,       /* Contains program counter */
  ARM_F0_REGNUM = 16,       /* first floating point register */
  ARM_F3_REGNUM = 19,       /* last floating point argument register */
  ARM_F7_REGNUM = 23,       /* last floating point register */
  ARM_FPS_REGNUM = 24,      /* floating point status register */
  ARM_PS_REGNUM = 25,       /* Contains processor status */
  ARM_WR0_REGNUM,       /* WMMX data registers.  */
  ARM_WR15_REGNUM = ARM_WR0_REGNUM + 15,
  ARM_WC0_REGNUM,       /* WMMX control registers.  */
  ARM_WCSSF_REGNUM = ARM_WC0_REGNUM + 2,
  ARM_WCASF_REGNUM = ARM_WC0_REGNUM + 3,
  ARM_WC7_REGNUM = ARM_WC0_REGNUM + 7,
  ARM_WCGR0_REGNUM,     /* WMMX general purpose registers.  */
  ARM_WCGR3_REGNUM = ARM_WCGR0_REGNUM + 3,
  ARM_WCGR7_REGNUM = ARM_WCGR0_REGNUM + 7,
  ARM_D0_REGNUM,        /* VFP double-precision registers.  */
  ARM_D31_REGNUM = ARM_D0_REGNUM + 31,
  ARM_FPSCR_REGNUM,

  ARM_NUM_REGS,

  /* Other useful registers.  */
  ARM_FP_REGNUM = 11,       /* Frame register in ARM code, if used.  */
  THUMB_FP_REGNUM = 7,      /* Frame register in Thumb code, if used.  */
  ARM_NUM_ARG_REGS = 4,
  ARM_LAST_ARG_REGNUM = ARM_A4_REGNUM,
  ARM_NUM_FP_ARG_REGS = 4,
  ARM_LAST_FP_ARG_REGNUM = ARM_F3_REGNUM
};


/* Number of machine registers.  The only define actually required
   is gdbarch_num_regs.  The other definitions are used for documentation
   purposes and code readability.  */
/* For 26 bit ARM code, a fake copy of the PC is placed in register 25 (PS)
   (and called PS for processor status) so the status bits can be cleared
   from the PC (register 15).  For 32 bit ARM code, a copy of CPSR is placed
   in PS.  */
#define NUM_FREGS   8   /* Number of floating point registers.  */
#define NUM_SREGS   2   /* Number of status registers.  */
#define NUM_GREGS   16  /* Number of general purpose registers.  */

/* Size of integer registers.  */
#define INT_REGISTER_SIZE       4


/* Instruction condition field values.  */
#define INST_EQ     0x0
#define INST_NE     0x1
#define INST_CS     0x2
#define INST_HS     0x2
#define INST_CC     0x3
#define INST_LO     0x3
#define INST_MI     0x4
#define INST_PL     0x5
#define INST_VS     0x6
#define INST_VC     0x7
#define INST_HI     0x8
#define INST_LS     0x9
#define INST_GE     0xa
#define INST_LT     0xb
#define INST_GT     0xc
#define INST_LE     0xd
#define INST_AL     0xe
#define INST_NV     0xf

#define FLAG_N      0x80000000
#define FLAG_Z      0x40000000
#define FLAG_C      0x20000000
#define FLAG_V      0x10000000

#define CPSR_T      0x20

#define XPSR_T      0x01000000


#define reverse2b(obj)	( ((obj&0xFF)<<8) | ((obj&0xFF00)>>8) )
#define reverse4b(obj)	\
   ( ((obj&0xFF)<<24) | ((obj&0xFF00)<<8) | ((obj&0xFF0000)>>8) | ((obj&0xFF000000)>>24) )

/* Support routines for instruction parsing.  */
#define submask(x) ((1L << ((x) + 1)) - 1)
#define bit(obj,st) (((obj) >> (st)) & 1)
#define bits(obj,st,fn) (((obj) >> (st)) & submask ((fn) - (st)))
#define sbits(obj,st,fn) \
  ((long) (bits(obj,st,fn) | ((long) bit(obj,fn) * ~ submask (fn - st))))
#define BranchDest(addr,instr) \
  ((CORE_ADDR) (((unsigned long) (addr)) + 8 + (sbits (instr, 0, 23) << 2)))


/* Addresses for calling Thumb functions have the bit 0 set.
   Here are some macros to test, set, or clear bit 0 of addresses.  */
#define IS_THUMB_ADDR(addr)		((addr) & 1)
#define MAKE_THUMB_ADDR(addr)	((addr) | 1)
#define UNMAKE_THUMB_ADDR(addr)	((addr) & ~1)


/* Return number of 1-bits in VAL.  */
static int
bitcount (unsigned long val)
{
	int nbits;
	for (nbits = 0; val != 0; nbits++)
		val &= val - 1;     /* Delete rightmost 1-bit in val.  */
	return nbits;
}


/* Return 1 if the 16-bit Thumb instruction INST might change
   control flow, 0 otherwise.  */
static int
thumb_instruction_changes_pc (unsigned short inst)
{
  if ((inst & 0xff00) == 0xbd00)	/* pop {rlist, pc} */
    return 1;

  if ((inst & 0xf000) == 0xd000)	/* conditional branch */
    return 1;

  if ((inst & 0xf800) == 0xe000)	/* unconditional branch */
    return 1;

  if ((inst & 0xff00) == 0x4700)	/* bx REG, blx REG */
    return 1;

  if ((inst & 0xff87) == 0x4687)	/* mov pc, REG */
    return 1;

  if ((inst & 0xf500) == 0xb100)	/* CBNZ or CBZ.  */
    return 1;

  return 0;
}


/* Return 1 if the 32-bit Thumb instruction in INST1 and INST2
   might change control flow, 0 otherwise.  */
static int
thumb2_instruction_changes_pc (unsigned short inst1, unsigned short inst2)
{
  if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0x8000) == 0x8000)
    {
      /* Branches and miscellaneous control instructions.  */

      if ((inst2 & 0x1000) != 0 || (inst2 & 0xd001) == 0xc000)
	{
	  /* B, BL, BLX.  */
	  return 1;
	}
      else if (inst1 == 0xf3de && (inst2 & 0xff00) == 0x3f00)
	{
	  /* SUBS PC, LR, #imm8.  */
	  return 1;
	}
      else if ((inst2 & 0xd000) == 0x8000 && (inst1 & 0x0380) != 0x0380)
	{
	  /* Conditional branch.  */
	  return 1;
	}

      return 0;
    }

  if ((inst1 & 0xfe50) == 0xe810)
    {
      /* Load multiple or RFE.  */

      if (bit (inst1, 7) && !bit (inst1, 8))
	{
	  /* LDMIA or POP */
	  if (bit (inst2, 15))
	    return 1;
	}
      else if (!bit (inst1, 7) && bit (inst1, 8))
	{
	  /* LDMDB */
	  if (bit (inst2, 15))
	    return 1;
	}
      else if (bit (inst1, 7) && bit (inst1, 8))
	{
	  /* RFEIA */
	  return 1;
	}
      else if (!bit (inst1, 7) && !bit (inst1, 8))
	{
	  /* RFEDB */
	  return 1;
	}

      return 0;
    }

  if ((inst1 & 0xffef) == 0xea4f && (inst2 & 0xfff0) == 0x0f00)
    {
      /* MOV PC or MOVS PC.  */
      return 1;
    }

  if ((inst1 & 0xff70) == 0xf850 && (inst2 & 0xf000) == 0xf000)
    {
      /* LDR PC.  */
      if (bits (inst1, 0, 3) == 15)
	return 1;
      if (bit (inst1, 7))
	return 1;
      if (bit (inst2, 11))
	return 1;
      if ((inst2 & 0x0fc0) == 0x0000)
	return 1;

      return 0;
    }

  if ((inst1 & 0xfff0) == 0xe8d0 && (inst2 & 0xfff0) == 0xf000)
    {
      /* TBB.  */
      return 1;
    }

  if ((inst1 & 0xfff0) == 0xe8d0 && (inst2 & 0xfff0) == 0xf010)
    {
      /* TBH.  */
      return 1;
    }

  return 0;
}



static int
condition_true (unsigned long cond, unsigned long status_reg)
{
	if (cond == INST_AL || cond == INST_NV)
		return 1;

	switch (cond)
	{
		case INST_EQ:
			return ((status_reg & FLAG_Z) != 0);
		case INST_NE:
			return ((status_reg & FLAG_Z) == 0);
		case INST_CS:
			return ((status_reg & FLAG_C) != 0);
		case INST_CC:
			return ((status_reg & FLAG_C) == 0);
		case INST_MI:
			return ((status_reg & FLAG_N) != 0);
		case INST_PL:
			return ((status_reg & FLAG_N) == 0);
		case INST_VS:
			return ((status_reg & FLAG_V) != 0);
		case INST_VC:
			return ((status_reg & FLAG_V) == 0);
		case INST_HI:
			return ((status_reg & (FLAG_C | FLAG_Z)) == FLAG_C);
		case INST_LS:
			return ((status_reg & (FLAG_C | FLAG_Z)) != FLAG_C);
		case INST_GE:
			return (((status_reg & FLAG_N) == 0) == ((status_reg & FLAG_V) == 0));
		case INST_LT:
			return (((status_reg & FLAG_N) == 0) != ((status_reg & FLAG_V) == 0));
		case INST_GT:
			return (((status_reg & FLAG_Z) == 0)
				&& (((status_reg & FLAG_N) == 0)
					== ((status_reg & FLAG_V) == 0)));
		case INST_LE:
			return (((status_reg & FLAG_Z) != 0)
					|| (((status_reg & FLAG_N) == 0)
						!= ((status_reg & FLAG_V) == 0)));
	}
	return 1;
}


static unsigned long
shifted_reg_val (unsigned long inst, int carry,
		unsigned long pc_val, unsigned long status_reg, arm_regs* regs)
{
	unsigned long res, shift;
	int rm = bits (inst, 0, 3);
	unsigned long shifttype = bits (inst, 5, 6);

	if (bit (inst, 4))
	{
		int rs = bits (inst, 8, 11);
		shift = (rs == 15 ? pc_val + 8
				: regs->uregs[ rs ] ) & 0xFF;
	}
	else
		shift = bits (inst, 7, 11);

	res = (rm == ARM_PC_REGNUM
			? (pc_val + (bit (inst, 4) ? 12 : 8))
			: regs->uregs[ rm ]);

	switch (shifttype)
	{
		case 0:			/* LSL */
			res = shift >= 32 ? 0 : res << shift;
			break;

		case 1:			/* LSR */
			res = shift >= 32 ? 0 : res >> shift;
			break;

		case 2:			/* ASR */
			if (shift >= 32)
				shift = 31;
			res = ((res & 0x80000000L)
					? ~((~res) >> shift) : res >> shift);
			break;

		case 3:			/* ROR/RRX */
			shift &= 31;
			if (shift == 0)
				res = (res >> 1) | (carry ? 0x80000000L : 0);
			else
				res = (res >> shift) | (res << (32 - shift));
			break;
	}

	return res & 0xffffffff;
}



/* Remove useless bits from addresses in a running program.  */
static CORE_ADDR
arm_addr_bits_remove (CORE_ADDR val)
{
	/* On M-profile devices, do not strip the low bit from EXC_RETURN
	   (the magic exception return address).  */
	/*
	if (gdbarch_tdep (gdbarch)->is_m
			&& (val & 0xfffffff0) == 0xfffffff0)
		return val;
	*/

	if (arm_apcs_32)
		return UNMAKE_THUMB_ADDR (val);
	else
		return (val & 0x03fffffc);
}


/* Return the size in bytes of the complete Thumb instruction whose
   first halfword is INST1.  */

static int
thumb_insn_size (unsigned short inst1)
{
	if ((inst1 & 0xe000) == 0xe000 && (inst1 & 0x1800) != 0)
		return 4;
	else
		return 2;
}

static int
thumb_advance_itstate (unsigned int itstate)
{
	/* Preserve IT[7:5], the first three bits of the condition.  Shift
	   the upcoming condition flags left by one bit.  */
	itstate = (itstate & 0xe0) | ((itstate << 1) & 0x1f);

	/* If we have finished the IT block, clear the state.  */
	if ((itstate & 0x0f) == 0)
		itstate = 0;

	return itstate;
}



CORE_ADDR
arm_get_next_pc(pid_t pid, CORE_ADDR pc, arm_regs* regs, int * code_pass);

CORE_ADDR
thumb_get_next_pc(pid_t pid, CORE_ADDR pc, arm_regs* regs, int * code_pass);
