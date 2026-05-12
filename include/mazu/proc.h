/* SPDX-License-Identifier: MIT */
/* User-space process management.
 *
 * Each process owns a set of user-mapped pages, a fixed capability table
 * (see struct cap_space) that backs POSIX file descriptors and other
 * object handles, and a bounded thread group. The process table is a
 * small static array (PROC_MAX entries).
 */

#ifndef MAZU_PROC_H
#define MAZU_PROC_H

#include <mazu/base.h>
#include <mazu/byte.h>
#include <mazu/cap.h>
#include <mazu/error.h>
#include <mazu/paging.h>
#include <mazu/spinlock.h>
#include <mazu/uaccess.h>
#include <mazu/vfs.h>
#include <mazu/waitqueue.h>

/* PSE51 signal state.  31 signals (1-31) in a 32-bit bitmask. */
#define SIG_MAX 32
typedef void (*sig_handler_fn_t)(i32);
struct sigaction_entry {
    sig_handler_fn_t handler;
    u32 sa_mask;
    u32 sa_flags;
};

/* Per-process signal state. The blocked mask and signal-frame chain live
 * per-thread (struct sched_task::td_sig); the disposition table stays
 * per-process per POSIX. proc_pending holds process-directed signals that have
 * not yet been claimed by any specific thread; the return-to-user delivery
 * path folds it into each thread's local pending view, preserving the bit even
 * if the thread that the sender first observed has since exited.
 */
struct signal_state {
    struct sigaction_entry actions[SIG_MAX];
    u32 proc_pending;
};

#define PROC_MAX 16
#define PROC_PAGES_MAX 32
#define PROC_VMA_MAX 8

/* Maximum live tasks (threads) per process. The per-thread state migration
 * (sigmask / signal-frame chain / robust futex / errno TLS) has landed, so
 * PROC_THREAD_MAX > 1 is now safe.  Bumping this number costs
 * PROC_THREAD_MAX * (USER_STACK_SIZE + PAGE_SIZE) of user VA inside the
 * per-process slot, plus PROC_THREAD_MAX pointers in struct proc::tasks[]; both
 * are bounded.
 */
#define PROC_THREAD_MAX 4
#define PROC_FD_MAX (CAP_SPACE_SLOTS - PROC_THREAD_MAX)
#define PROC_FD_STDIN 0
#define PROC_FD_STDOUT 1
#define PROC_FD_STDERR 2
#define PROC_PATH_MAX 256

/* lseek whence values (POSIX). */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

/* Magic number for struct proc (ASCII 'proc'). */
#define PROC_MAGIC 0x70726F63U

/* VMA permission flags (match PT_FLAG_* for convenience). */
#define VMA_PERM_READ BIT(0)
#define VMA_PERM_WRITE BIT(1)
#define VMA_PERM_EXEC BIT(3)

/* Virtual Memory Area: describes a contiguous user-space region with uniform
 * permissions.  Used for user-pointer validation and W^X enforcement. Populated
 * during task creation (code + stack VMAs).
 */
struct vma {
    vaddr_t base;
    sz len;
    u16 perms; /* VMA_PERM_* flags */
    bool active;
};

enum proc_state {
    PROC_STATE_FREE = 0,
    PROC_STATE_EMBRYO,   /* allocated but not yet runnable */
    PROC_STATE_RUNNING,  /* actively executing or schedulable */
    PROC_STATE_SLEEPING, /* blocked on I/O or condition */
    PROC_STATE_STOPPED,  /* halted by signal/debugger */
    PROC_STATE_ZOMBIE,   /* exited, awaiting parent reap */
};

/* Per-process VA slot size: divide user address space equally among PROC_MAX
 * processes. Each slot contains code, data, and stack. Slot i occupies
 * [USER_CODE_BASE + i*PROC_SLOT_SIZE, USER_CODE_BASE + (i+1)*PROC_SLOT_SIZE).
 */
#define PROC_SLOT_SIZE \
    (((0x40000000UL - 0x00010000UL) / PROC_MAX) & ~(0x1000UL - 1))

struct proc {
    u64 watchdog_heartbeat_ms;
    /* Bounded per-process task list. Slots are stable because each slot owns
     * a fixed user-stack VA band. All readers and writers must hold
     * proc_table_lock; there is no lock-free walk path today.
     */
    struct sched_task *tasks[PROC_THREAD_MAX];
    u8 n_tasks;
    u8 leader_idx;          /* slot of the elected thread-group leader. */
    u8 reserved_task_slots; /* bitmask of in-flight slot reservations. */
    u64 exited_cpu_time_us; /* CPU time retained from reaped worker threads. */
    struct wait_queue_head thread_event_wq; /* stable wake source for joins */

    /* Per-process VA window (set during proc_alloc based on PID slot). */
    vaddr_t va_code_base; /* start of code region */
    vaddr_t va_stack_top; /* top of stack (grows down) */

    sz cwd_len;
    sz n_user_pages;
    sz n_vmas;
    struct vma vmas[PROC_VMA_MAX];
    struct {
        paddr_t paddr;
        vaddr_t vaddr;
    } user_pages[PROC_PAGES_MAX];
    struct cap_space cap_space;
    u32 magic;
    u32 generation;
    u8 vma_cache_read;
    u8 vma_cache_write;
    enum proc_state state;
    /* Single-shot guard for proc_exit so a race between sys_exit and a
     * SIGKILL-driven exit on the same proc cannot double-execute the
     * teardown (futex_exit_robust_list, posix_timer_teardown_proc,
     * sync_handle_teardown_proc).  Set under proc_table_lock; cleared
     * implicitly by proc_alloc's memset on slot reuse.
     */
    bool is_exiting;
    i32 exit_code;
    /* Per-process syscall whitelist.  0 = unrestricted.
     * Two u64 words cover syscall numbers 0..127.
     */
    u64 syscall_allow[2];
    spinlock_t fd_lock;
    spinlock_t sig_lock;
    struct signal_state sig_state;

    /* Robust futex list moved per-thread (struct sched_task::
     * td_robust_list_head / _futex_offset / _pending) so each thread unwinds
     * its own held futexes on exit, matching Linux semantics.
     */

    u16 pid;
    u16 parent_pid;
    u32 parent_generation;
    char name[32];
    char cwd[PROC_PATH_MAX];
};

struct_result(proc, struct proc *);

extern spinlock_t proc_table_lock;

/* Return a human-readable name for a process state. */
static inline struct str proc_state_name(enum proc_state s)
{
    switch (s) {
    case PROC_STATE_FREE:
        return STR("free");
    case PROC_STATE_EMBRYO:
        return STR("embryo");
    case PROC_STATE_RUNNING:
        return STR("running");
    case PROC_STATE_SLEEPING:
        return STR("sleeping");
    case PROC_STATE_STOPPED:
        return STR("stopped");
    case PROC_STATE_ZOMBIE:
        return STR("zombie");
    default:
        return STR("???");
    }
}

/* Return the thread-group leader, or NULL if the proc has no live threads
 * (post-detach during proc_exit). Cheap inline accessor. Callers that need the
 * leader to remain valid across a sleep must hold proc_table_lock for the
 * duration of the dereference, same as the previous direct read of p->task.
 */
static inline struct sched_task *proc_thread_group_leader(struct proc *p)
{
    if (!p || p->n_tasks == 0)
        return NULL;
    if (p->leader_idx >= PROC_THREAD_MAX)
        return NULL;
    return p->tasks[p->leader_idx];
}

/* Return the index of the given live task inside p->tasks[], or
 * PROC_THREAD_MAX if the task is not attached.
 */
static inline u8 proc_task_slot(struct proc *p, const struct sched_task *td)
{
    if (!p || !td)
        return PROC_THREAD_MAX;
    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        if (p->tasks[i] == td)
            return i;
    }
    return PROC_THREAD_MAX;
}

/* Attach a task to the process. Returns false if the task list is full (today:
 * if a task is already attached). Caller must hold proc_table_lock.
 */
bool proc_attach_task(struct proc *p, struct sched_task *td);
bool proc_attach_task_slot(struct proc *p, struct sched_task *td, u8 slot);
bool proc_reserve_thread_slot(struct proc *p, u8 *out_slot);
void proc_release_thread_slot(struct proc *p, u8 slot);
void proc_release_thread_stack(struct proc *p, u8 slot);
i64 proc_reap_exited_thread_locked(struct proc *p, struct sched_task *td);
void proc_reap_exited_thread(struct proc *p, struct sched_task *td);

/* Detach the given task from the process. The task's ->proc field is cleared.
 * Caller must hold proc_table_lock.
 */
void proc_detach_task(struct proc *p, struct sched_task *td);

/* Initialize the process table.  Called once during boot. */
void proc_init(void);
u64 proc_table_lock_irqsave(void);
void proc_table_unlock_irqrestore(u64 flags);
u64 proc_fd_lock_irqsave(struct proc *p);
void proc_fd_unlock_irqrestore(struct proc *p, u64 flags);
u64 proc_sig_lock_irqsave(struct proc *p);
void proc_sig_unlock_irqrestore(struct proc *p, u64 flags);

/* Allocate a new process entry.  Returns NULL if the table is full. */
struct proc *proc_alloc(void);

/* Close a single file descriptor in a process. */
void proc_close_fd(struct proc *p, i32 fd);
void proc_close_fd_locked(struct proc *p, i32 fd);

/* Free a process entry back to the table. */
void proc_free(struct proc *p);

/* Look up a process by PID. */
struct proc *proc_find(u16 pid);

/* Look up a process by PID.  Caller must hold proc_table_lock. */
struct proc *proc_find_locked(u16 pid);

/* Snapshot the live descendant tree rooted at root/root_generation.
 * Includes root itself when still live. Returns the number of entries
 * written to out/out_generations (up to max).
 */
sz proc_collect_descendants_locked(struct proc *root,
                                   u32 root_generation,
                                   struct proc **out,
                                   u32 *out_generations,
                                   sz max);
sz proc_collect_descendants(struct proc *root,
                            u32 root_generation,
                            struct proc **out,
                            u32 *out_generations,
                            sz max);

/* Iterate all active processes, calling cb for each. */
typedef void (*proc_iter_cb_t)(struct proc *p, void *ctx);
void proc_for_each(proc_iter_cb_t cb, void *ctx);

/* Allocate a physical page, map it at vaddr with the given perms (PT_FLAG_*),
 * and record it in proc->user_pages for cleanup.
 */
__must_check struct result proc_map_user_page(struct proc *p,
                                              vaddr_t vaddr,
                                              u16 perms);
bool proc_unmap_user_page(struct proc *p, vaddr_t vaddr);

/* Unmap and free all user pages belonging to the process. */
void proc_free_user_pages(struct proc *p);

/* Register a VMA in the process.  Returns 0 on success, -ENOMEM if full. */
__must_check i32 proc_add_vma(struct proc *p, vaddr_t base, sz len, u16 perms);
bool proc_remove_vma(struct proc *p, vaddr_t base, sz len);

/* Check whether [addr, addr+len) falls entirely within a registered VMA. */
bool proc_vma_contains(struct proc *p, ptr addr, sz len);

/* Check spatial containment AND that the VMA's perms satisfy required_perms.
 * Pass 0 for required_perms to check containment only (same as above).
 */
bool proc_vma_check_access(struct proc *p,
                           ptr addr,
                           sz len,
                           u16 required_perms);

/* Transition a process to a new state with validity checking.
 * DEBUG_ASSERT fires on invalid transitions (e.g., FREE -> ZOMBIE).
 */
void proc_set_state(struct proc *p, enum proc_state new_state);

/* Block the calling task until a child of 'parent' enters ZOMBIE state.
 * On success, *out_pid receives the child's PID and *out_code receives the
 * child's exit code.  The zombie is reaped (transitioned to FREE).
 * Returns 0 on success, -ECHILD if the process has no children.
 */
i32 proc_wait_child(struct proc *parent, u16 *out_pid, i32 *out_code);

/* Wake the parent's child_wq (called when a child enters ZOMBIE). */
void proc_notify_parent(struct proc *child);

/* Load a flat binary into process memory at USER_CODE_BASE. */
__must_check struct result proc_load_flat(struct proc *p,
                                          struct byte_view binary);

/* Load an ELF binary, mapping PT_LOAD segments at their vaddr. */
__must_check struct result proc_load_elf(struct proc *p,
                                         struct byte_view binary);

/* Return true if pid is absent from the process table or already ZOMBIE. */
bool proc_is_missing_or_zombie(u16 pid);

/* Reparent all live children of 'parent' to PID 1 (init). If PID 1 is missing,
 * zombie children are auto-reaped.  Must be called before the parent
 * transitions to ZOMBIE. Acquires proc_table_lock internally.
 */
void proc_reparent_children(struct proc *parent);

/* Full process exit: reparent children, transition to ZOMBIE, notify parent or
 * auto-reap if orphaned.  Idempotent: a second concurrent caller is a no-op.
 */
void proc_exit(struct proc *p, i32 exit_code);

/* Count the number of children (any state != FREE) of a given parent PID.
 * Acquires proc_table_lock internally.
 */
sz proc_count_children(u16 parent_pid);

#endif /* MAZU_PROC_H */
