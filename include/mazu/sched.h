/* SPDX-License-Identifier: MIT */
/* Hard-RT scheduler state and APIs.
 *
 * Invariants exposed by this interface:
 * - kernel preemption is mandatory in every build
 * - trap exit is the only place that consumes need_resched
 * - every runnable non-idle task owns a finite timer-backed quantum
 * - READY tasks live on a run queue, RUNNING tasks live only in pcpu->curthread
 */

#ifndef MAZU_SCHED_H
#define MAZU_SCHED_H

#include <isr.h>
#include <mazu/base.h>
#include <mazu/callout.h>
#include <mazu/error.h>
#include <mazu/list.h>
#include <mazu/spinlock.h>
#include <mazu/stringdef.h>
#include <mazu/time.h>
#include <mazu/tls.h>
#include <mazu/waitqueue.h>

/* Direct defconfig copies may omit implicit Kconfig defaults.
 * Keep scheduler buildable by providing the canonical defaults here.
 * Mazu is a hard-RT kernel: preemption is mandatory, not optional.
 */
#ifndef CONFIG_SCHED_PREEMPTIVE
#define CONFIG_SCHED_PREEMPTIVE 1
#endif

#if !CONFIG_SCHED_PREEMPTIVE
#error "Mazu requires CONFIG_SCHED_PREEMPTIVE=y for hard-RT behavior"
#endif

#ifndef CONFIG_SCHED_NPRIO
#define CONFIG_SCHED_NPRIO 4
#endif

/* Magic number for struct sched_task (ASCII 'task'). */
#define TASK_MAGIC 0x7461736BU

struct proc; /* forward declaration; defined in <mazu/proc.h> */

#define TASK_STACK_SIZE 0x4000
#define TASK_GUARD_SIZE PAGE_SIZE

/* Priority levels: higher numeric value = higher priority.
 * CONFIG_SCHED_NPRIO determines the total number of levels (default 4).
 */
#define SCHED_PRIO_IDLE 0
#define SCHED_PRIO_NORMAL 1
#define SCHED_PRIO_HIGH 2
#define SCHED_PRIO_REALTIME 3

#ifdef CONFIG_SCHED_DEADLINE

#define SCHED_POLICY_NORMAL 0
#define SCHED_POLICY_DEADLINE 1
/* Per-task EDF scheduling entity.  All time values in timer ticks.
 *
 * Lifecycle:
 *   sched_dl_setattr() validates and sets dl_runtime/dl_deadline/dl_period.
 *   On activation: dl_abs_deadline = now + dl_deadline, dl_remaining =
 * dl_runtime. Per context switch: dl_remaining decremented by run duration.
 *   Budget exhausted (dl_remaining == 0): throttled, replenish callout armed.
 *   Replenish callout: dl_remaining = dl_runtime, dl_abs_deadline += dl_period.
 *   Deadline miss: dl_abs_deadline < now when task becomes runnable.
 */
struct sched_dl_entity {
    u64 dl_runtime;      /* budget per period (ticks) */
    u64 dl_deadline;     /* relative deadline from period start (ticks) */
    u64 dl_period;       /* period length (ticks) */
    u64 dl_abs_deadline; /* absolute deadline of current job */
    u64 dl_remaining;    /* remaining runtime budget this period */
    struct callout dl_replenish_callout;
    bool dl_throttled; /* budget exhausted, awaiting replenish */
    bool dl_active;    /* task is admitted as a DL task */
};

#ifndef CONFIG_SCHED_DL_UTIL_THRESHOLD
#define CONFIG_SCHED_DL_UTIL_THRESHOLD 95
#endif
#endif /* CONFIG_SCHED_DEADLINE */

/* Scheduling domain: CPU time budget enforcement per task group.
 * Once consumed_ticks reaches quantum_ticks, the domain becomes DEPLETED and
 * member tasks stop re-entering READY until the refill callout restores the
 * budget. This keeps domain throttling timer-driven and deterministic.
 */
#define SCHED_DOMAIN_MAX_MEMBERS 8

enum sched_domain_state {
    DOMAIN_ACTIVE = 0,
    DOMAIN_DEPLETED = 1,
};

#ifdef CONFIG_MIXED_CRIT
/* Criticality levels for scheduling domains. */
#define SCHED_DOMAIN_CRIT_LO 0
#define SCHED_DOMAIN_CRIT_HI 1

/* Escalation state: NORMAL (both running) or ESCALATED (LO suspended). */
enum mc_escalation_state {
    MC_NORMAL = 0,
    MC_ESCALATED = 1,
};

#ifndef CONFIG_MIXED_CRIT_HI_PCT
#define CONFIG_MIXED_CRIT_HI_PCT 70
#endif
#endif /* CONFIG_MIXED_CRIT */

struct sched_domain {
    u64 quantum_ticks;  /* budget allowed per period */
    u64 period_ticks;   /* period length in ticks */
    u64 consumed_ticks; /* ticks consumed this period */
    u64 next_refill;    /* absolute rdtime of next refill */
    enum sched_domain_state state;
    struct callout refill_callout;
    struct sched_task *members[SCHED_DOMAIN_MAX_MEMBERS];
    u32 nr_members;

#ifdef CONFIG_MIXED_CRIT
    u8 criticality; /* SCHED_DOMAIN_CRIT_HI or _LO */
    enum mc_escalation_state mc_state;
    struct sched_domain *mc_peer; /* peer domain (HI<->LO link) */
#endif
};

/* Initialize a scheduling domain with the given budget and period. */
void sched_domain_init(struct sched_domain *dom,
                       u64 quantum_ticks,
                       u64 period_ticks);

/* Attach a task to a domain.  Returns 0 on success, -1 if full. */
int sched_domain_attach(struct sched_domain *dom, struct sched_task *task);

/* Detach a task from its domain. */
void sched_domain_detach(struct sched_task *task);

typedef void (*sched_callback_func_t)(void *context);
typedef void (*sched_block_cleanup_fn_t)(struct sched_task *task, void *ctx);

enum td_state {
    TD_STATE_READY = 0,
    TD_STATE_RUNNING = 1,
    TD_STATE_SLEEPING = 2,
    TD_STATE_SEM_WAIT = 3,
    TD_STATE_YIELDING = 4,
    TD_STATE_TERMINATING = 5,
    TD_STATE_BLOCKED = 6,
#ifdef CONFIG_SCHED_DEADLINE
    TD_STATE_DL_THROTTLED = 7,
#endif
};

struct sched_task {
    byte guard[TASK_GUARD_SIZE] __aligned(PAGE_SIZE);
    byte stack[TASK_STACK_SIZE] __aligned(16);
    struct trap_frame td_tf; /* frame restored on the next trap exit */

    u32 magic; /* TASK_MAGIC - validated in debug builds */
    u16 id;
    enum td_state state;

    u64 cpu_time_us;     /* accumulated CPU time in microseconds */
    u64 switch_in_ticks; /* rdtime value when this task was last switched in */

    u8 td_prio;        /* current scheduling priority (may be boosted) */
    u8 td_base_prio;   /* original priority (for inheritance reset) */
    u16 td_starvation; /* consecutive skips counter for anti-starvation */

    u16 td_quantum; /* timer ticks per time slice (0 only for per-hart idle) */

    i32 td_affinity; /* hart affinity: -1 = any, >= 0 = pinned to hart */
    u32 td_last_cpu; /* last hart this task ran on (for migration detection) */

    sched_callback_func_t callback;
    void *context;
    bool must_not_exit; /* if true, returning from callback triggers panic */

    struct proc *proc; /* owning user process, or NULL for kernel tasks */
    struct sched_domain *domain; /* CPU budget domain, or NULL (unlimited) */

    struct list_head sleep_list;
    struct list_head kres_list; /* per-task resource auto-cleanup chain */
    struct list_head
        pi_held_mutexes; /* PI mutexes currently held by this task */

    struct callout td_sleep_callout;   /* drives timed wakeups back to READY */
    struct callout td_quantum_callout; /* drives hard-RT quantum expiry */
    u64 td_wakeup_ticks; /* rdtime when the task most recently became READY */

    /* Exponential decay load estimation (managarm-inspired).
     * Updated on each context switch: load_avg decays toward zero when
     * the task is sleeping, and grows toward LOAD_SCALE when running.
     * Used by the SMP load balancer to make migration decisions.
     */
    u64 load_avg; /* fixed-point Q16 load estimate */

    /* EEVDF scheduling state (Earliest Eligible Virtual Deadline First).
     * vruntime: accumulated virtual CPU ticks consumed by this task.
     * vdeadline: vruntime + virtual_slice, set on enqueue.
     * Pick-next selects the eligible task with earliest vdeadline within
     * each priority level, bounding wake-to-run latency to one slice.
     */
    u64 vruntime;
    u64 vdeadline;

#ifdef CONFIG_SCHED_DEADLINE
    u8 td_policy; /* SCHED_POLICY_NORMAL or SCHED_POLICY_DEADLINE */
    struct sched_dl_entity
        dl; /* valid when td_policy == SCHED_POLICY_DEADLINE */
#endif

    u64 last_activity_ms; /* timestamp of last observable activity
                           * (yield/rx/http)
                           */
    bool hung; /* set by watchdog when task exceeds inactivity timeout */
    bool td_cleanup_queued; /* once set, task is already staged for deferred
                             * destruction and must not be queued again
                             */
    sched_block_cleanup_fn_t td_block_cleanup;
    void *td_block_cleanup_ctx;

    /* Per-thread TLS array for PSE51 errno and kernel-internal slots.
     * Indexed by enum tls_entry.  Zeroed on task creation.
     */
    uptr tls[MAX_TLS_ENTRY];

    /* Per-thread signal state. POSIX requires the blocked mask to be per-thread
     * (pthread_sigmask). The signal-frame trampoline state is also per-thread
     * because each thread runs handlers on its own user stack, so process-wide
     * chain would corrupt with concurrent delivery once threads become real
     * (PROC_THREAD_MAX > 1). The pending mask is per-thread to give the future
     * thread-directed signal path (pthread_kill, SIGEV_THREAD_ID) somewhere to
     * deposit its bit; today, signal_send walks tasks[] and ORs into elected
     * thread's td_sig.pending.
     *
     * Lifetime: zeroed on task creation. Read/written under proc->sig_lock (the
     * lock scope stays per-proc; the data lives per-task).
     */
    struct {
        u32 pending;
        u32 blocked;
        ptr frame_top;
        ptr frame_prev;
        u32 frame_cookie;
        u32 frame_prev_cookie;
        /* Signal mask to restore on return-to-user after sigsuspend.
         * sys_sigsuspend_h captures the prior blocked mask here and
         * sets sigsuspend_active = true; signal_deliver / SIG_IGN
         * dequeue consult these to wire the original mask into the
         * signal frame so sigreturn restores it instead of the
         * temporary suspend mask.
         */
        u32 sigsuspend_saved_blocked;
        bool sigsuspend_active;
        /* Signal set this thread is parked on in sigtimedwait.
         * signal_send-style writers check it before nudging the
         * thread, so a sleeping sigtimedwait thread is woken only
         * by a signal that matches its set (eliminating spurious
         * wakeups).  0 means the thread is not in sigtimedwait.
         */
        u32 sigwait_set;
    } td_sig;

    /* Per-thread robust futex list. Linux semantics: the kernel walks this on
     * thread exit to unlock orphaned futexes that the dying thread held. Lives
     * per-task because each thread holds its own locks; today there is one
     * thread per process so behavior matches the previous per-process layout
     * exactly.
     */
    ptr td_robust_list_head;
    i32 td_robust_futex_offset;
    ptr td_robust_pending;

    /* PSE51 thread lifecycle (pthread_create / _join / _detach / _exit).
     * td_join_state runs FREE -> JOINABLE -> EXITED -> REAPED, or FREE ->
     * JOINABLE -> DETACHED -> auto-reaped after exit.
     * td_exit_code is populated by SYS_THREAD_EXIT or the implicit return path;
     * readers wait on td_join_wq for a JOINABLE thread to reach EXITED. State
     * transitions use atomic operations; task-list membership changes are
     * serialized separately under proc_table_lock.
     *
     * Embedded waitqueue (rather than allocated) keeps thread join inside the
     * bounded RTOS budget: no heap on the create or join hot paths.
     */
    enum {
        TD_JOIN_FREE = 0, /* slot is free; never been a user thread */
        TD_JOIN_JOINABLE, /* live, joinable */
        TD_JOIN_DETACHED, /* live, detached (no one will join) */
        TD_JOIN_EXITED,   /* exit value populated, waiting for join */
        TD_JOIN_REAPED,   /* joined or auto-reaped; resources released */
    } td_join_state;
    i32 td_exit_code;
    struct wait_queue_head td_join_wq;
    bool td_exit_started;
    i16 td_cap_slot;

    /* PSE51 cancellation state (pthread_cancel / _setcancelstate /
     * _setcanceltype / _testcancel).  td_cancel_pending is set by
     * pthread_cancel and consumed at the next cancellation point.
     * td_cancel_disabled disables cancellation entirely.  ASYNC type
     * is treated as DEFERRED here because Mazu has no in-kernel
     * cancellation points other than blocking syscalls (which check
     * the flag on entry); ASYNC interruption inside arbitrary user
     * code would require user-space libc cooperation that the
     * kernel layer cannot provide on its own.
     */
    bool td_cancel_pending;
    bool td_cancel_disabled;
};

/* Initialize the scheduling subsystem.
 * The current flow becomes task 0 and is inserted as bootstrap idle-priority
 * thread for the boot hart. After initialization, all runnable work is selected
 * by the scheduler and preempted by the timer path; callers do not need to
 * cooperate beyond using the blocking APIs that change task state explicitly.
 */
void sched_init(void);

/* Create a new task at the given priority level. */
struct result sched_create_task_prio(sched_callback_func_t callback,
                                     void *context,
                                     u8 prio);

/* Create a new task at SCHED_PRIO_NORMAL (default). */
struct result sched_create_task(sched_callback_func_t callback, void *context);

/* Like sched_create_task, but the task is expected to run forever. If the
 * callback returns, the kernel panics immediately; an unexpected return from
 * an infinite-loop task indicates a bug or corrupted state, not a recoverable
 * error.
 */
struct result sched_create_task_noreturn(sched_callback_func_t callback,
                                         void *context);

/* Like sched_create_task_noreturn, but at the given priority level. */
struct result sched_create_task_noreturn_prio(sched_callback_func_t callback,
                                              void *context,
                                              u8 prio);

/* Create a user-mode task. The task will sret into U-mode at 'entry' with
 * sp = USER_STACK_TOP. 'p' is the owning process (must already have its code
 * pages mapped). The user stack pages are mapped by this function.
 */
struct result sched_create_user_task(struct proc *p, ptr entry, u8 prio);

/* Create an additional user thread inside an existing process for
 * pthread_create. The caller passes the user-mode entry point and a single
 * argument (the POSIX pthread_create arg, placed in a0 on first dispatch).
 * Returns 0 on success and writes the new task pointer to *out_td; returns
 * a negative errno on failure (in which case *out_td is unchanged).
 */
i32 sched_create_user_thread(struct proc *p,
                             ptr u_entry,
                             ptr u_arg,
                             u8 prio,
                             u32 inherited_sigmask,
                             struct sched_task **out_td);

/* Free a user thread that exited in JOINABLE state and has now been
 * reaped via SYS_THREAD_JOIN. The caller must have transitioned
 * td_join_state from EXITED to REAPED under proc_sig_lock so no other
 * thread can race the free.
 */
void sched_reap_user_thread(struct sched_task *dead);

/* Return the ID of the task that is currently running.
 * Before sched_init(), returns 0 so early boot and post-init task 0 share the
 * same stable identity.
 */
u16 sched_current_id(void);

/* Block the current task for at least 'duration' milliseconds.
 * The task leaves RUNNING immediately, a callout re-enqueues it later, and trap
 * exit picks another runnable task right away. Wakeup latency after the minimum
 * delay remains bounded by higher-priority runnable work.
 */
void sleep_ms(struct time_ms duration);

struct sched_task_info {
    u16 id;
    enum td_state state;
    u8 prio;
    u64 cpu_time_us;
    sched_callback_func_t callback;
    u64 last_activity_ms;
    bool hung;
};

/* Return a short human-readable name for a thread state. */
static inline struct str td_state_name(enum td_state s)
{
    switch (s) {
    case TD_STATE_READY:
        return STR("ready");
    case TD_STATE_RUNNING:
        return STR("running");
    case TD_STATE_SLEEPING:
        return STR("sleeping");
    case TD_STATE_SEM_WAIT:
        return STR("sem_wait");
    case TD_STATE_YIELDING:
        return STR("yielding");
    case TD_STATE_TERMINATING:
        return STR("terminat");
    case TD_STATE_BLOCKED:
        return STR("blocked");
#ifdef CONFIG_SCHED_DEADLINE
    case TD_STATE_DL_THROTTLED:
        return STR("dl_throt");
#endif
    default:
        return STR("???");
    }
}

typedef void (*sched_task_iter_cb_t)(struct sched_task_info info, void *ctx);

/* Iterate all known tasks visible to the scheduler: current tasks, READY tasks,
 * and tasks still linked from the sleep list.
 */
void sched_for_each_task(sched_task_iter_cb_t cb, void *ctx);

/* Called only from trap_dispatch after the current task has left RUNNING.
 * Enqueues the outgoing task when appropriate, picks the next runnable task,
 * performs accounting, and returns the sole trap frame that may be restored.
 */
struct sched_task *sched_schedule(struct sched_task *old);

#if CONFIG_SMP
/* Enter the scheduler on a secondary hart.
 * Installs that hart's idle thread, publishes curthread, and transfers control
 * to the same trap/timer-driven scheduling regime as the boot hart.
 */
void sched_enter_secondary(void);
#endif

/* Enqueue a task to an appropriate CPU's per-CPU run queue.
 * Handles CPU selection and locking internally.  Used by waitqueue
 * wake, sleep callout callbacks, and new task creation paths.
 */
void sched_enqueue_ready(struct sched_task *task);

/* Return the currently running task (wrapper around get_pcpu()->curthread). */
struct sched_task *sched_current_task(void);

/* Per-thread TLS accessors.  Defined here because they need the full
 * sched_task definition and sched_current_task().
 */
static inline uptr tls_get(enum tls_entry entry)
{
    struct sched_task *td = sched_current_task();
    if (!td)
        return 0;
    return td->tls[entry];
}

static inline void tls_set(enum tls_entry entry, uptr val)
{
    struct sched_task *td = sched_current_task();
    if (!td)
        return;
    td->tls[entry] = val;
}

struct sched_latency_stats {
    u64 wakeup_latency_max_us;
    u64 wakeup_latency_hist[6];
};

/* Mark the timestamp of a READY transition for wakeup-latency telemetry. */
void sched_note_wakeup(struct sched_task *task);

/* Transition a blocked task back to READY and enqueue it.
 * This is the canonical wake path used by wait queues and timer callbacks.
 */
void sched_wake_ready(struct sched_task *task);

/* Force-wake a sleeping task (signal delivery).
 * Cancels the sleep callout and removes from global_sleep_list.
 * No-op if the task is not TD_STATE_SLEEPING.
 */
void sched_wake_sleeping(struct sched_task *td);

/* Wake a task blocked in a cancellation point.
 * If the task has stack-backed wait state, run its registered cleanup hook
 * first so it is safely unlinked before being re-enqueued.
 */
void sched_cancel_blocked(struct sched_task *task);

/* Register or clear a deferred cleanup hook for stack-backed blocking state.
 * The hook runs before the task stack is freed.
 */
void sched_set_block_cleanup(struct sched_task *task,
                             sched_block_cleanup_fn_t fn,
                             void *ctx);
void sched_clear_block_cleanup(struct sched_task *task);

/* Snapshot scheduler wakeup-latency telemetry counters. */
void sched_get_latency_stats(struct sched_latency_stats *out);

/* Record forward progress on the current task.
 * Updates the task watchdog stamp and the hart heartbeat without changing
 * scheduling state.
 */
void sched_note_activity(void);

/* Context-switch statistics for telemetry. */
struct sched_ctxsw_stats {
    u64 nr_ctxsw;          /* total context switches (sum of all harts) */
    u64 avg_cycles;        /* average switch cost in timer ticks */
    u64 max_cycles;        /* worst-case switch cost in timer ticks */
    u64 nr_migrations;     /* total cross-hart task migrations */
    u64 nr_remote_wakeups; /* total cross-hart wakeups (IPI-sent) */
};

void sched_get_ctxsw_stats(struct sched_ctxsw_stats *out);

/* Watchdog statistics for telemetry. */
struct sched_watchdog_stats {
    u32 nr_hung;     /* number of currently hung tasks */
    u32 nr_warnings; /* total warnings issued */
};

void sched_get_watchdog_stats(struct sched_watchdog_stats *out);

/* Per-hart heartbeat stats for telemetry.
 * A stale heartbeat indicates a hart stopped making scheduler/trap/timer
 * progress, not merely that a task ran for a long time.
 */
struct sched_hart_watchdog_stats {
    u64 heartbeat_age_us; /* time since last heartbeat stamp */
    bool stale;           /* true if heartbeat is stale */
    bool idle;            /* true if hart is parked in wfi */
};

/* Snapshot per-hart heartbeat state.  Returns 0 on success, -1 if
 * cpu is out of range.
 */
int sched_get_hart_watchdog(u32 cpu, struct sched_hart_watchdog_stats *out);

/* Domain observability: snapshot of a scheduling domain's state. */
struct sched_domain_stats {
    u64 quantum_ticks;
    u64 period_ticks;
    u64 consumed_ticks;
    u32 nr_members;
    u32 state; /* 0 = ACTIVE, 1 = DEPLETED */
};

/* Named kernel domains for built-in task groups.
 * SCHED_DOMAIN_WEB:  web server and HTTP handler tasks.
 * SCHED_DOMAIN_SYS:  system tasks (watchdog, retransmit, etc.).
 * SCHED_DOMAIN_COUNT: sentinel - number of built-in domains.
 */
#define SCHED_DOMAIN_WEB 0
#define SCHED_DOMAIN_SYS 1
#define SCHED_DOMAIN_COUNT 2

/* Snapshot a named domain's state.
 * Returns 0 on success, -1 if domain_id is out of range or domains are not
 * initialized.
 */
int sched_domain_get_stats(u32 domain_id, struct sched_domain_stats *out);

/* Return a pointer to a named kernel domain for task attachment.
 * Returns NULL if domain_id is out of range or domains are not initialized.
 */
struct sched_domain *sched_get_kernel_domain(u32 domain_id);

/* Trigger a supervisor software interrupt to reschedule the current hart.
 * The caller must have already changed its task state away from RUNNING when it
 * expects trap exit to switch away.
 */
void sched_yield_trap(void);

/* Switch sp to new_sp and call fn(arg).  Used to move off one stack
 * onto another before entering a loop (e.g., idle thread startup).
 * Defined in arch/riscv64/sched.c.
 */
__attribute__((noreturn)) void sched_call_on_stack(u64 new_sp,
                                                   void (*fn)(void *),
                                                   void *arg);

#ifdef CONFIG_SCHED_DEADLINE
/* User-visible scheduling attributes for SYS_SCHED_SETATTR/GETATTR. */
struct sched_attr {
    u32 policy; /* SCHED_POLICY_NORMAL or SCHED_POLICY_DEADLINE */
    u32 pad;    /* alignment */
    u64 runtime_ns;
    u64 deadline_ns;
    u64 period_ns;
};

/* Set deadline scheduling parameters.  Performs admission control.
 * Returns 0 on success, -EINVAL on bad params, -EBUSY on admission failure.
 */
int sched_dl_setattr(struct sched_task *task,
                     u64 runtime_ns,
                     u64 deadline_ns,
                     u64 period_ns);

/* Revert a task to SCHED_POLICY_NORMAL, releasing its utilization. */
void sched_dl_clearattr(struct sched_task *task);

/* Initialize per-CPU deadline run queues.  Called from sched_init(). */
void sched_dl_init(void);

/* Initialize DL fields in a newly allocated task. */
void sched_dl_task_init(struct sched_task *task);

/* Cancel DL callouts for a dying task. */
void sched_dl_task_destroy(struct sched_task *task);

/* Charge DL budget on context switch out.  May throttle the task. */
void sched_dl_charge(struct sched_task *task, u64 delta_ticks);

/* Pick the earliest-deadline task from a CPU's DL run queue.
 * Caller holds pcpu_runq_lock[cpu].  Returns NULL if none runnable.
 */
struct sched_task *sched_dl_pick_next(u32 cpu);

/* Enqueue a deadline task onto a CPU's DL run queue.
 * Caller holds pcpu_runq_lock[cpu].
 */
void sched_dl_enqueue(struct sched_task *task, u32 cpu);

/* Deadline scheduling stats for telemetry. */
struct sched_dl_stats {
    u32 nr_admitted;
    u64 nr_deadline_misses;
    u64 nr_throttles;
    u64 nr_replenishments;
};
void sched_dl_get_stats(struct sched_dl_stats *out);
#endif /* CONFIG_SCHED_DEADLINE */

#ifdef CONFIG_MIXED_CRIT
/* Initialize mixed-criticality for a domain pair.
 * hi_dom gets criticality=HI, lo_dom gets criticality=LO.
 * They become peers for escalation/recovery signaling.
 */
void sched_mc_init_pair(struct sched_domain *hi_dom,
                        struct sched_domain *lo_dom);

/* Check escalation state after HI domain budget accounting.
 * Called from domain refill callback and budget charge paths.
 */
void sched_mc_check_escalation(struct sched_domain *hi_dom);

/* Check recovery: called after HI domain budget is replenished.
 * If HI load dropped below threshold, resume LO domain.
 */
void sched_mc_check_recovery(struct sched_domain *hi_dom);
#endif /* CONFIG_MIXED_CRIT */

#endif /* MAZU_SCHED_H */
