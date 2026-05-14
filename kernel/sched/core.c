/* SPDX-License-Identifier: MIT */
#include <mazu/asm.h>
#include <mazu/assert.h>
#include <mazu/callout.h>
#include <mazu/cap.h>
#include <mazu/cpumask.h>
#include <mazu/eventlog.h>
#include <mazu/init.h>
#include <mazu/initgraph.h>
#include <mazu/ipi.h>
#include <mazu/kvalloc.h>
#include <mazu/paging.h>
#include <mazu/pcpu.h>
#include <mazu/proc.h>
#include <mazu/sched.h>
#include <mazu/spinlock.h>
#include <mazu/uaccess.h>
#include "../kres.h"
#include "../lockdep.h"
#include "../proc/signal.h"
#include "../sync/mutex.h"
#include "waitqueue.h"

/* Lock ordering (global):
 *   wq->lock  ->  pcpu_runq_lock[cpu]  (never reversed)
 *   sched_lock  ->  pcpu_runq_lock[cpu]  (never reversed)
 *
 * pcpu_runq_lock[cpu] protects: pcpu_runq[cpu][], pcpu_runq_bitmap[cpu],
 * and run-queue membership on that CPU.
 *
 * sched_lock protects: global_sleep_list, global_next_id.
 *
 * Per-hart fields (curthread, idle, need_resched, sched_deferred_free)
 * are accessed without lock - each hart writes only its own slot.
 *
 * Idle-steal: a hart may spin_trylock another hart's pcpu_runq_lock
 * to pull migratable tasks.  trylock prevents deadlock when two harts
 * attempt to steal from each other simultaneously.
 *
 * ISR context may acquire pcpu_runq_lock via spin_lock (not irqsave)
 * because ISRs already run with interrupts disabled on this hart.
 */
static bool global_sched_initialized;
spinlock_t sched_lock = SPINLOCK_INITIALIZER;

static struct sched_task global_main_task;
static u16 global_next_id;
static struct list_head global_sleep_list;

/* Per-CPU run queues and bitmaps.  Each hart has its own set of priority-
 * sorted run queues, protected by pcpu_runq_lock[cpu].  This eliminates
 * the global sched_lock bottleneck on the scheduler hot path.
 */
static struct list_head pcpu_runq[MAX_CPUS][CONFIG_SCHED_NPRIO];
static u32 pcpu_runq_bitmap[MAX_CPUS];
spinlock_t pcpu_runq_lock[MAX_CPUS];

static_assert(CONFIG_SCHED_NPRIO <= U32_WIDTH,
              "CONFIG_SCHED_NPRIO must fit "
              "runq_bitmap width");

/* Per-hart idle tasks.  BSP uses idle_tasks[0], secondaries use
 * idle_tasks[cpuid].  Statically allocated so they don't need
 * guard-page unmapping.
 */
static struct sched_task idle_tasks[MAX_CPUS];

/* Deferred cleanup: a terminating task can't free its own memory (the
 * trapframe is still referenced on return from trap_dispatch).  The
 * next context switch via sched_schedule() does the actual free.
 * Per-hart slot avoids SMP races (each hart only writes its own).
 */
static struct sched_task *sched_deferred_free[MAX_CPUS];

/* Wakeup latency telemetry: measured from transition to READY
 * (waitqueue/callout wake) to the task becoming RUNNING.
 */
static u64 sched_wakeup_latency_max_us;
static u64 sched_wakeup_latency_hist[6];

/* Default time-slice quanta per priority level (in timer ticks, ~10ms each).
 * 0 is reserved for the per-hart idle thread; all runnable work is
 * timer-preemptible.
 */
static const u16 sched_default_quantum[CONFIG_SCHED_NPRIO] = {
    [SCHED_PRIO_IDLE] = 0,     /* idle never arms a quantum callout */
    [SCHED_PRIO_NORMAL] = 1,   /* 10ms */
    [SCHED_PRIO_HIGH] = 2,     /* 20ms */
    [SCHED_PRIO_REALTIME] = 5, /* 50ms */
};

/* Forward declarations. */
static void sched_task_entry(void);
static void quantum_callout_cb(void *arg);
#if CONFIG_SMP
static void sched_update_load_avg(struct sched_task *task, u64 delta_ticks);
static void sched_decay_sleeping_load(struct sched_task *task);
#endif
#if __DEBUG__ > 0
static void sched_check_invariants(struct sched_task *next, u32 cpuid);
#endif

static inline u64 sched_deadline_saturate(u64 now, u64 qticks)
{
    return (qticks > U64_MAX - 1 - now) ? (U64_MAX - 1) : now + qticks;
}

/* Per-CPU run queue ops

 * Select the best CPU for a task that needs to be enqueued.
 * Pinned tasks go to their affinity CPU.  Previously-run tasks go back
 * to their last CPU for cache warmth.  New tasks go to the caller's CPU.
 */
static u32 sched_select_cpu(struct sched_task *task)
{
    i32 aff = __atomic_load_n(&task->td_affinity, __ATOMIC_ACQUIRE);
    if (aff >= 0)
        return (u32) aff;
    if (task->td_last_cpu != U32_MAX && pcpu_array[task->td_last_cpu].online)
        return task->td_last_cpu;
    return get_cpuid();
}

/* Internal: enqueue task to a specific CPU's run queue.
 * Caller holds pcpu_runq_lock[cpu].
 */
static void sched_enqueue_cpu_locked(struct sched_task *task, u32 cpu)
{
    assert(task->td_prio < CONFIG_SCHED_NPRIO);

    /* Guard against double-enqueue: if the node is already linked into
     * a run queue (e.g., a callout callback enqueued this task during
     * the current ISR), skip the insert.  After list_del_init in
     * sched_pick_next_local, the node is self-referential; after
     * list_add_tail it points elsewhere.
     */
    if (task->sleep_list.next != &task->sleep_list)
        return;

#if CONFIG_SCHED_DEADLINE
    /* Deadline tasks go to the separate DL run queue. */
    if (task->td_policy == SCHED_POLICY_DEADLINE && task->dl.dl_active) {
        sched_dl_enqueue(task, cpu);
        return;
    }
#endif

    /* Domain budget check: don't enqueue if the task's domain is
     * depleted.  The refill callout will re-enqueue when active.
     * Cache the pointer: concurrent sched_domain_detach may clear it.
     */
    struct sched_domain *dom = __atomic_load_n(&task->domain, __ATOMIC_RELAXED);
    if (dom &&
        __atomic_load_n(&dom->state, __ATOMIC_ACQUIRE) == DOMAIN_DEPLETED) {
        sched_set_task_state(task, TD_STATE_BLOCKED);
        /* Double-check: refill may have raced and set ACTIVE. */
        if (__atomic_load_n(&dom->state, __ATOMIC_ACQUIRE) == DOMAIN_ACTIVE) {
            sched_set_task_state(task, TD_STATE_READY);
        } else {
            return;
        }
    }

    sched_set_task_state(task, TD_STATE_READY);

    list_add_tail(&pcpu_runq[cpu][task->td_prio], &task->sleep_list);
    pcpu_runq_bitmap[cpu] |= BIT(task->td_prio);
    if (task->td_prio > SCHED_PRIO_IDLE)
        KTRACE("event=ready_queued cpu=%hu tid=%hu prio=%hu", (u32) cpu,
               (u32) task->id, (u32) task->td_prio);

    struct pcpu *pc = &pcpu_array[cpu];
    struct sched_task *cur = pc->curthread;

    /* Run-queue telemetry: count enqueue and track activity gauge. */
    pc->nr_enqueue++;
    pc->nr_sched_ops++;
    if (pc->nr_sched_ops > pc->max_sched_ops)
        pc->max_sched_ops = pc->nr_sched_ops;

    /* Signal reschedule on the target CPU if the enqueued task has
     * higher priority than what that CPU is currently running.
     */
    if (cur && task->td_prio > cur->td_prio)
        __atomic_store_n(&pc->need_resched, 1, __ATOMIC_RELEASE);

    /* Tick restart: a second task became runnable at the current task's
     * priority on the target CPU.  If that CPU's current task's quantum
     * callout is NOT armed, arm it now so preemption is re-enabled.
     */
    if (cur && cur->td_quantum > 0 && cur->td_prio == task->td_prio &&
        !callout_pending(&cur->td_quantum_callout)) {
        u64 qticks = time_ms_to_ticks((u64) cur->td_quantum * 10);
        callout_set_ticks(&cur->td_quantum_callout, qticks, quantum_callout_cb,
                          cur);
        /* Update preemption deadline on local hart only.  For remote
         * CPUs the IPI below will trigger re-evaluation.
         */
        if (cpu == get_cpuid()) {
            u64 now = time_rdtime();
            pc->preempt_deadline = sched_deadline_saturate(now, qticks);
            update_pcpu_deadline();
        }
    }

#if CONFIG_SMP
    /* If the target CPU is remote, send an IPI to trigger reschedule.
     * Skip IPI for idle-priority tasks to avoid ping-pong between
     * idle harts.  Track remote wakeups for telemetry.
     */
    if (task->td_prio > SCHED_PRIO_IDLE && cpu != get_cpuid()) {
#if CONFIG_SCHED_DEADLINE
        /* RT-aware IPI filtering: skip IPI if the target hart
         * is running an RT task, unless:
         * (a) the new task is a DL task with an earlier deadline, or
         * (b) the new task has higher fixed priority, or
         * (c) the new task is also DL (always worth re-evaluating).
         */
        struct pcpu *tpc = &pcpu_array[cpu];
        bool skip = false;
        if (__atomic_load_n(&tpc->rt_active, __ATOMIC_ACQUIRE)) {
            skip = true;
            u64 remote_dl =
                __atomic_load_n(&tpc->rt_deadline, __ATOMIC_RELAXED);
            if (task->td_policy == SCHED_POLICY_DEADLINE &&
                task->dl.dl_abs_deadline < remote_dl)
                skip = false;
            if (task->td_prio >= SCHED_PRIO_REALTIME)
                skip = false;
        }
        if (!skip) {
#endif
            get_pcpu()->nr_remote_wakeups++;
            KTRACE("event=remote_wakeup src_cpu=%hu dst_cpu=%hu tid=%hu",
                   (u32) get_cpuid(), (u32) cpu, (u32) task->id);
            ipi_send(cpu, IPI_SCHED);
#if CONFIG_SCHED_DEADLINE
        }
#endif
    }
#endif
}

/* Public: enqueue a task to an appropriate CPU's run queue.
 * Handles locking internally.  Called from waitqueue wake, sleep
 * callout callback, and new task creation paths.
 */
void sched_enqueue_ready(struct sched_task *task)
{
#if CONFIG_SMP
    /* Decay load_avg for time spent sleeping/blocked so the load
     * balancer doesn't treat I/O-bound tasks as CPU-heavy.
     */
    sched_decay_sleeping_load(task);
#endif
    u32 cpu = sched_select_cpu(task);
    lockdep_acquire(LOCK_LEVEL_SCHED);
    u64 flags = spin_lock_irqsave(&pcpu_runq_lock[cpu]);
    sched_enqueue_cpu_locked(task, cpu);
    spin_unlock_irqrestore(&pcpu_runq_lock[cpu], flags);
    lockdep_release(LOCK_LEVEL_SCHED);
}

/* Dequeue telemetry helper: update counters on the specified CPU.
 * When dequeuing from the local hart, pass get_cpuid().  When
 * stealing from a remote hart, pass the source CPU so the gauge
 * decrements on the correct hart.
 */
static void sched_dequeue_telemetry(struct sched_task *task, u32 src_cpu)
{
    struct pcpu *dpc = &pcpu_array[src_cpu];
    dpc->nr_dequeue++;
    if (dpc->nr_sched_ops > 0)
        dpc->nr_sched_ops--;
    if (task->td_wakeup_ticks != 0) {
        u64 now = time_rdtime();
        if (now >= task->td_wakeup_ticks)
            dpc->total_wait_ticks += now - task->td_wakeup_ticks;
    }
}

/* Dequeue a specific task from its priority queue on the given CPU.
 * Caller holds pcpu_runq_lock[cpu].
 */
static struct sched_task *sched_dequeue_task_locked(struct sched_task *task,
                                                    u32 cpu)
{
    list_del_init(&task->sleep_list);
    if (list_empty(&pcpu_runq[cpu][task->td_prio]))
        pcpu_runq_bitmap[cpu] &= ~BIT(task->td_prio);
    sched_dequeue_telemetry(task, cpu);
    if (task->td_prio > SCHED_PRIO_IDLE)
        KTRACE("event=ready_dequeued cpu=%hu tid=%hu", (u32) cpu,
               (u32) task->id);
    return task;
}

/* Pick the highest-priority runnable task from a specific CPU's queue.
 * Caller holds pcpu_runq_lock[cpu].  Returns NULL if no suitable task.
 * Priority levels still dominate: a higher-priority task always wins,
 * and equal-priority tasks rotate FIFO by quantum expiry or voluntary
 * yield.
 */
static struct sched_task *sched_pick_from_cpu_locked(u32 cpu)
{
#if CONFIG_SCHED_DEADLINE
    /* DL tasks always preempt priority-level tasks. */
    struct sched_task *dl_next = sched_dl_pick_next(cpu);
    if (dl_next)
        return dl_next;
#endif

    u32 bm = pcpu_runq_bitmap[cpu];
    struct sched_task *task;
    while (bm) {
        int p = 31 - __builtin_clz(bm);
        list_for_each_entry_safe (&pcpu_runq[cpu][p], task, struct sched_task,
                                  sleep_list) {
            return sched_dequeue_task_locked(task, cpu);
        }
        bm &= ~BIT(p);
    }
    return NULL;
}

/* Pick the highest-priority task from the local CPU's queue.
 * If only the idle task remains, attempt to steal a non-idle,
 * non-pinned task from another hart's queue (pull migration).
 * Caller holds pcpu_runq_lock[cpuid].
 *
 * The per-hart idle task guarantees at least one task is always
 * runnable, so this function never returns NULL.
 */
static struct sched_task *sched_pick_next_local(u32 cpuid)
{
    struct sched_task *next = sched_pick_from_cpu_locked(cpuid);
    if (next && next->td_prio > SCHED_PRIO_IDLE)
        return next;

    /* Only idle-priority task available locally.  Keep it as fallback
     * and attempt idle-steal from other harts.
     */
    struct sched_task *idle_fallback = next;

#if CONFIG_SMP
    /* Try to steal a non-idle, migratable task from another hart.
     * Use spin_trylock to avoid deadlock with concurrent stealers.
     */
    struct sched_task *task;
    for (u32 i = 0; i < MAX_CPUS; i++) {
        if (i == cpuid || !pcpu_array[i].online)
            continue;
        if (!spin_trylock(&pcpu_runq_lock[i]))
            continue;

        u32 bm = pcpu_runq_bitmap[i];
        /* Only consider non-idle priorities. */
        bm &= ~BIT(SCHED_PRIO_IDLE);
        struct sched_task *stolen = NULL;
        while (bm) {
            int p = 31 - __builtin_clz(bm);
            list_for_each_entry_safe (&pcpu_runq[i][p], task, struct sched_task,
                                      sleep_list) {
                /* Skip pinned tasks; can't migrate them. */
                if (__atomic_load_n(&task->td_affinity, __ATOMIC_RELAXED) >= 0)
                    continue;
                list_del_init(&task->sleep_list);
                if (list_empty(&pcpu_runq[i][p]))
                    pcpu_runq_bitmap[i] &= ~BIT(p);
                stolen = task;
                break;
            }
            if (stolen)
                break;
            bm &= ~BIT(p);
        }

        spin_unlock(&pcpu_runq_lock[i]);

        if (stolen) {
            /* Re-enqueue the idle fallback taken from this hart's own queue. */
            if (idle_fallback) {
                list_add_tail(&pcpu_runq[cpuid][idle_fallback->td_prio],
                              &idle_fallback->sleep_list);
                pcpu_runq_bitmap[cpuid] |= BIT(idle_fallback->td_prio);
            }
            sched_dequeue_telemetry(stolen, i);
            return stolen;
        }
    }
#endif /* CONFIG_SMP */

    /* Nothing to steal; run the idle fallback. */
    if (idle_fallback)
        return idle_fallback;

    crash("sched_pick_next: no runnable task\n");
}

/* Quantum expiry callout: fires when the current task's time slice is up.
 * Runs in ISR context; sets need_resched so the trap exit path forces a
 * context switch.
 */
static void quantum_callout_cb(void *arg)
{
    (void) arg;
    /* Only signal - let trap_dispatch set td->state = READY.
     * Setting both state and need_resched would cause need_resched
     * to leak (trap_dispatch only clears it when state == RUNNING).
     */
    __atomic_store_n(&get_pcpu()->need_resched, 1, __ATOMIC_RELEASE);
}

/* Complete scheduler decision: enqueue the outgoing task, pick the next,
 * perform CPU-time accounting and deferred cleanup, update curthread.
 *
 * Called from trap_dispatch() when td->state != TD_STATE_RUNNING.
 * Returns the next task to restore (never NULL).
 */
static inline void sched_stage_deferred_free(struct sched_task *task, u32 cpuid)
{
    if (!task || task->td_cleanup_queued)
        return;

    task->td_cleanup_queued = true;
    DEBUG_ASSERT(sched_deferred_free[cpuid] == NULL);
    sched_deferred_free[cpuid] = task;
}

/* Cancel callouts and tear down DL state. Safe to call multiple times
 * because callout_cancel_sync is idempotent and sched_dl_task_destroy
 * removes the DL entity if present. Separated from the final
 * kvalloc_free so a joinable user thread can be cancelled at exit
 * but reaped later by SYS_THREAD_JOIN.
 */
static void sched_task_cancel_runtime(struct sched_task *dead)
{
    callout_cancel_sync(&dead->td_sleep_callout);
    callout_cancel_sync(&dead->td_quantum_callout);
#if CONFIG_SCHED_DEADLINE
    sched_dl_task_destroy(dead);
#endif
}

/* Final teardown: poison magic, restore the guard page, free the task
 * struct. Caller must guarantee no other reader holds a reference.
 */
static void sched_task_finalize_free(struct sched_task *dead)
{
    dead->magic = 0xDEADDEADU;
    paging_map_page((vaddr_t) dead->guard, (paddr_t) dead->guard, PT_FLAG_RW);
    kvalloc_free(byte_array_new((void *) dead, sizeof(*dead)));
}

/* Free a dead task's stack and callouts. Synchronization resources
 * (PI mutexes, block cleanup, kres) were already released
 * immediately in sched_schedule() to avoid latency under NO_HZ.
 *
 * For user threads, this is the sole place the JOIN_JOINABLE ->
 * JOIN_EXITED transition happens. Running here (on the cleanup
 * hart, after the dying thread has fully descheduled) guarantees
 * any joiner observing EXITED is safe to reap: no remaining hart
 * is executing the task body. Joinable threads skip the final
 * kvalloc_free; the joiner finishes that step via
 * sched_reap_user_thread once it claims the REAPED transition.
 */
static void sched_destroy_dead_task(struct sched_task *dead)
{
    assert(dead);
    sched_task_cancel_runtime(dead);
    if (dead->proc && dead->td_join_state == TD_JOIN_JOINABLE) {
        /* Atomic flip JOINABLE -> EXITED so a concurrent
         * sys_thread_detach observing JOINABLE cannot also try to
         * mark EXITED. After the flip, wake any pending joiners.
         */
        u8 prev = (u8) TD_JOIN_JOINABLE;
        u8 next = (u8) TD_JOIN_EXITED;
        if (__atomic_compare_exchange_n((u8 *) &dead->td_join_state, &prev,
                                        next, false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_RELAXED)) {
            wake_up(&dead->td_join_wq, I32_MAX);
            wake_up(&dead->proc->thread_event_wq, I32_MAX);
            return; /* leave the struct allocated for the joiner */
        }
        /* Lost the race to detach: state is now DETACHED, fall
         * through to free.
         */
    }
    if (dead->proc && dead->td_join_state == TD_JOIN_DETACHED)
        proc_reap_exited_thread(dead->proc, dead);
    sched_task_finalize_free(dead);
}

/* Reap a user thread that exited in JOINABLE state. The caller (the
 * SYS_THREAD_JOIN handler or proc_exit) must have already won the
 * transition from TD_JOIN_EXITED to TD_JOIN_REAPED via
 * __atomic_compare_exchange_n so only one reaper runs the final
 * kvalloc_free.
 */
void sched_reap_user_thread(struct sched_task *dead)
{
    if (!dead)
        return;
    /* Cancellation already ran in sched_destroy_dead_task. Calling
     * again is idempotent (callout_cancel_sync handles already-
     * cancelled callouts).
     */
    sched_task_cancel_runtime(dead);
    sched_task_finalize_free(dead);
}

void sched_set_block_cleanup(struct sched_task *task,
                             sched_block_cleanup_fn_t fn,
                             void *ctx)
{
    assert(task);
    task->td_block_cleanup = fn;
    task->td_block_cleanup_ctx = ctx;
}

void sched_clear_block_cleanup(struct sched_task *task)
{
    assert(task);
    task->td_block_cleanup = NULL;
    task->td_block_cleanup_ctx = NULL;
}

struct sched_task *sched_schedule(struct sched_task *old)
{
    struct pcpu *pc = get_pcpu();
    u32 cpuid = pc->cpuid;
    u64 ctxsw_start = time_rdtime();
    MAGIC_CHECK(old, TASK_MAGIC);
    DEBUG_ASSERT(old == pc->curthread);

    /* Stamp per-hart heartbeat unconditionally.  Reaching sched_schedule()
     * proves the hart's timer, interrupt, and scheduler machinery are all
     * functioning -- this is what the per-hart watchdog detects.  A single
     * CPU-bound task being re-picked (next == old) is NOT a hart stall;
     * task-level hangs are caught by watchdog_check_task() via
     * last_activity_ms.
     */
    __atomic_store_n(&pc->heartbeat_stamp, ctxsw_start, __ATOMIC_RELAXED);

#if CONFIG_SCHED_DEADLINE
    /* Charge DL budget on context switch out.  May throttle the task. */
    if (old->td_policy == SCHED_POLICY_DEADLINE && old->dl.dl_active) {
        u64 dl_delta = ctxsw_start - old->switch_in_ticks;
        sched_dl_charge(old, dl_delta);
    }
#endif

    /* Domain budget accounting: charge the outgoing task's domain.
     * Cache the pointer because old is the current CPU's task, so the
     * domain will not be concurrently detached, but caching avoids
     * repeated loads.
     */
    struct sched_domain *old_dom = old->domain;
    if (old_dom) {
        u64 budget_delta = ctxsw_start - old->switch_in_ticks;
        u64 new_consumed = __atomic_add_fetch(&old_dom->consumed_ticks,
                                              budget_delta, __ATOMIC_RELAXED);
        if (__atomic_load_n(&old_dom->state, __ATOMIC_RELAXED) ==
                DOMAIN_ACTIVE &&
            new_consumed >= old_dom->quantum_ticks) {
            __atomic_store_n(&old_dom->state, DOMAIN_DEPLETED,
                             __ATOMIC_RELAXED);
            KTRACE("event=domain_depleted quantum=%lu consumed=%lu",
                   old_dom->quantum_ticks, new_consumed);
#if CONFIG_MIXED_CRIT
            if (old_dom->criticality == SCHED_DOMAIN_CRIT_HI)
                sched_mc_check_escalation(old_dom);
#endif
        }
    }

    /* Per-CPU critical section: enqueue old and pick next. */
    lockdep_acquire(LOCK_LEVEL_SCHED);
    u64 flags = spin_lock_irqsave(&pcpu_runq_lock[cpuid]);

    switch (old->state) {
    case TD_STATE_YIELDING:
        sched_set_task_state(old, TD_STATE_READY);
        /* fall through */
    case TD_STATE_READY:
        /* If the task's domain is depleted, block instead of enqueue.
         * The refill callout will re-enqueue when the budget resets.
         *
         * Race: refill_cb may fire between the state read and the
         * BLOCKED write.  refill_cb checks for TD_STATE_BLOCKED, so
         * if it ran while the task was still READY, the task would be skipped.
         * Re-check after setting BLOCKED: if domain is now ACTIVE,
         * undo the block and enqueue normally.
         */
        {
            struct sched_domain *odom = old->domain;
            if (odom && __atomic_load_n(&odom->state, __ATOMIC_ACQUIRE) ==
                            DOMAIN_DEPLETED) {
                sched_set_task_state(old, TD_STATE_BLOCKED);
                /* Double-check: refill may have raced and set ACTIVE. */
                if (__atomic_load_n(&odom->state, __ATOMIC_ACQUIRE) ==
                    DOMAIN_ACTIVE) {
                    sched_enqueue_cpu_locked(old, cpuid);
                }
                break;
            }
        }
        sched_enqueue_cpu_locked(old, cpuid);
        break;
    case TD_STATE_SLEEPING:
        /* sleep_ms already added to global_sleep_list and armed
         * the callout.  Nothing to do here.
         */
        break;
    case TD_STATE_TERMINATING:
        /* Don't enqueue; deferred-free handles cleanup below. */
        break;
    case TD_STATE_SEM_WAIT:
        /* fall through */
    case TD_STATE_BLOCKED:
        /* On a wait queue / sync primitive; wake path moves to READY. */
        break;
#if CONFIG_SCHED_DEADLINE
    case TD_STATE_DL_THROTTLED:
        /* Budget exhausted; replenishment callout will re-enqueue. */
        break;
#endif
    default:
        break;
    }

    bool old_needs_free =
        (old->state == TD_STATE_TERMINATING && !old->td_cleanup_queued);

    /* Release terminating task resources BEFORE picking next, so any
     * newly woken high-priority task (e.g. PI mutex inheritor) is
     * visible to sched_pick_next_local.  Drop the sched lock first
     * because cleanup takes WAITQ-level locks (lower ordering).
     */
    if (old_needs_free) {
        spin_unlock_irqrestore(&pcpu_runq_lock[cpuid], flags);
        lockdep_release(LOCK_LEVEL_SCHED);

        if (old->td_block_cleanup) {
            sched_block_cleanup_fn_t fn = old->td_block_cleanup;
            void *ctx = old->td_block_cleanup_ctx;
            sched_clear_block_cleanup(old);
            fn(old, ctx);
        }
        pi_mutex_release_all(old);
        kres_destroy_all(old);

        /* Re-acquire to pick next with the woken tasks on the queue. */
        lockdep_acquire(LOCK_LEVEL_SCHED);
        flags = spin_lock_irqsave(&pcpu_runq_lock[cpuid]);
    }

    struct sched_task *next = sched_pick_next_local(cpuid);
    MAGIC_CHECK(next, TASK_MAGIC);
    DEBUG_ASSERT(next->td_prio < CONFIG_SCHED_NPRIO);

    spin_unlock_irqrestore(&pcpu_runq_lock[cpuid], flags);
    lockdep_release(LOCK_LEVEL_SCHED);

    /* Free the stack of the task that terminated on the previous switch. */
    if (sched_deferred_free[cpuid]) {
        struct sched_task *dead = sched_deferred_free[cpuid];
        sched_deferred_free[cpuid] = NULL;
        sched_destroy_dead_task(dead);
    }

    u64 now_ticks = time_rdtime();
    u64 delta_ticks = now_ticks - old->switch_in_ticks;
    old->cpu_time_us += time_ticks_to_us(delta_ticks);

#if CONFIG_SMP
    /* Update exponential-decay load average for the outgoing task. */
    sched_update_load_avg(old, delta_ticks);
#endif
    if (next->td_wakeup_ticks != 0) {
        /* Guard against cross-hart rdtime skew: if now_ticks appears
         * earlier than the wake stamp, skip this sample instead of
         * underflowing into a huge bogus latency value.
         */
        if (now_ticks >= next->td_wakeup_ticks) {
            u64 wake_us = time_ticks_to_us(now_ticks - next->td_wakeup_ticks);

            __atomic_fetch_add(
                &sched_wakeup_latency_hist[latency_us_to_bin(wake_us)], 1,
                __ATOMIC_RELAXED);

            u64 old_max =
                __atomic_load_n(&sched_wakeup_latency_max_us, __ATOMIC_RELAXED);
            while (wake_us > old_max &&
                   !__atomic_compare_exchange_n(
                       &sched_wakeup_latency_max_us, &old_max, wake_us, false,
                       __ATOMIC_RELAXED, __ATOMIC_RELAXED))
                ;
        }
        next->td_wakeup_ticks = 0;
    }
    next->switch_in_ticks = now_ticks;

    /* NO_HZ_FULL: only arm the quantum callout if another task is
     * runnable at the same priority level.  If only one task at this
     * priority, no preemption needed - zero timer interrupts.
     */
    if (next->td_quantum > 0 &&
        (pcpu_runq_bitmap[cpuid] & BIT(next->td_prio))) {
        u64 qticks = time_ms_to_ticks((u64) next->td_quantum * 10);
        callout_set_ticks(&next->td_quantum_callout, qticks, quantum_callout_cb,
                          next);
        u64 now = time_rdtime();
        pc->preempt_deadline = sched_deadline_saturate(now, qticks);
    } else {
        pc->preempt_deadline = U64_MAX;
    }
    update_pcpu_deadline();
    DEBUG_ASSERT((pc->preempt_deadline == U64_MAX) ==
                 !(next->td_quantum > 0 &&
                   (pcpu_runq_bitmap[cpuid] & BIT(next->td_prio))));

    if (old_needs_free)
        sched_stage_deferred_free(old, cpuid);

    pc->curthread = next;
    sched_set_task_state(next, TD_STATE_RUNNING);

#if CONFIG_SCHED_DEADLINE
    /* Update RT-active flag for IPI filtering.
     * Write deadline before active flag so a remote reader that sees
     * rt_active=true via acquire also sees the correct deadline.
     */
    if (next->td_policy == SCHED_POLICY_DEADLINE) {
        __atomic_store_n(&pc->rt_deadline, next->dl.dl_abs_deadline,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&pc->rt_active, true, __ATOMIC_RELEASE);
        mp_set_cpu_realtime(cpuid);
    } else if (next->td_prio >= SCHED_PRIO_REALTIME) {
        __atomic_store_n(&pc->rt_deadline, U64_MAX, __ATOMIC_RELAXED);
        __atomic_store_n(&pc->rt_active, true, __ATOMIC_RELEASE);
        mp_set_cpu_realtime(cpuid);
    } else {
        __atomic_store_n(&pc->rt_active, false, __ATOMIC_RELEASE);
        __atomic_store_n(&pc->rt_deadline, U64_MAX, __ATOMIC_RELAXED);
        mp_clear_cpu_realtime(cpuid);
    }
#endif

    if (next->td_prio > SCHED_PRIO_IDLE) {
        KTRACE("event=running_committed cpu=%hu tid=%hu", (u32) cpuid,
               (u32) next->id);
        if (next != old) {
            KTRACE("event=task_switched cpu=%hu prev=%hu next=%hu", (u32) cpuid,
                   (u32) old->id, (u32) next->id);
        }
    }

    /* Migration detection: if the task previously ran on a different hart,
     * count a migration event.  Skip the sentinel (U32_MAX) which
     * indicates a task that has never been scheduled.
     */
    if (next->td_last_cpu != U32_MAX && next->td_last_cpu != pc->cpuid)
        pc->nr_migrations++;
    next->td_last_cpu = pc->cpuid;

    /* Fix gp for task migration: _trap_entry restores gp from the
     * trapframe, and also uses it to find pcpu->intr_stack_top for
     * sscratch.  If the task last ran on a different hart, its saved
     * gp points to the wrong pcpu.  Always stamp the current hart's
     * pcpu so both gp and sscratch are correct after sret.
     */
    next->td_tf.gp = (u64) (uptr) pc;

    /* Update idle status for IPI notification.  Atomic store: cross-hart
     * readers (watchdog_check_harts, IPI sender) load with RELAXED.
     */
    bool going_idle = (next->td_prio == SCHED_PRIO_IDLE);
    __atomic_store_n(&pc->idle, going_idle, __ATOMIC_RELAXED);

    /* Maintain global CPU masks for cpumask-based IPI targeting. */
    if (going_idle)
        mp_set_cpu_idle(cpuid);
    else
        mp_clear_cpu_idle(cpuid);

    /* Context-switch telemetry: count and measure scheduler path cost.
     * Only count actual task transitions (skip when the same task is
     * reselected after a yield with no other candidate).
     */
    if (next != old) {
        u64 ctxsw_end = time_rdtime();
        u64 elapsed = ctxsw_end - ctxsw_start;
        pc->nr_ctxsw++;
        pc->ctxsw_cycles_total += elapsed;
        if (elapsed > pc->ctxsw_cycles_max)
            pc->ctxsw_cycles_max = elapsed;
    }

#if __DEBUG__ > 0
    sched_check_invariants(next, cpuid);
#endif

    return next;
}

/* Idle thread

 * The idle thread: last-resort runnable task at SCHED_PRIO_IDLE.
 * Loops doing wfi (waits for interrupt) then yields to check for newly
 * runnable tasks.  When entered via sret, SPIE restores SIE so timer
 * interrupts fire normally.
 */
/* Deep idle support. */

void pcpu_idle_enter(enum pcpu_idle_state state)
{
    struct pcpu *pc = get_pcpu();
    pc->idle_state = (u8) state;
}

void pcpu_idle_exit(void)
{
    struct pcpu *pc = get_pcpu();
    pc->idle_state = PCPU_IDLE_ACTIVE;
}

static void sched_idle_thread(void *ctx __unused)
{
    /* Ensure interrupts are enabled.  On the BSP this is a no-op (sret
     * already set SIE via SPIE).  On secondary harts, interrupts were
     * deliberately kept disabled until after sched_call_on_stack moved
     * sp off the interrupt stack - enabling here avoids the race where
     * a trap fires while sp and sscratch alias the same stack.
     */
    enable_interrupts();

    while (true) {
        /* wfi blocks until an interrupt fires.  If no callouts are
         * armed and no external interrupt source is active, wfi blocks
         * forever.  Only sleep when no other tasks are runnable -
         * otherwise yield immediately so real tasks run.
         */
        if (pcpu_runq_bitmap[get_cpuid()] == 0) {
            /* Determine idle depth.  Enter DEEP idle only if the next
             * callout deadline is far enough away (> threshold).
             */
            struct pcpu *pc = get_pcpu();
            u64 deadline = pc->timer_deadline;
            u64 now = time_rdtime();
            u64 threshold = time_ms_to_ticks(DEEP_IDLE_THRESHOLD_MS);

            if (deadline > now && (deadline - now) > threshold)
                pcpu_idle_enter(PCPU_IDLE_DEEP);
            else
                pcpu_idle_enter(PCPU_IDLE_SHALLOW);

            hlt();
            pcpu_idle_exit();
        }
        sleep_ms(time_ms_new(0));
    }
}

/* Tasks

 * Trigger a supervisor software interrupt (SSI) to enter trap_dispatch.
 * The trap handler observes the current task's state (YIELDING, SLEEPING,
 * or TERMINATING) and reschedules accordingly.
 *
 * ecall from S-mode goes to M-mode (OpenSBI), not the kernel trap handler, so
 * SSI (setting sip.SSIP) serves as the voluntary-yield mechanism.
 */
void sched_yield_trap(void)
{
    struct pcpu *pc = get_pcpu();
    struct sched_task *td = pc->curthread;
    if (td)
        __atomic_store_n(&td->last_activity_ms, time_current_ms().ms,
                         __ATOMIC_RELAXED);
    /* Stamp heartbeat on explicit yield as well: a hart can remain healthy
     * while taking the fast return path and avoiding sched_schedule().
     */
    __atomic_store_n(&pc->heartbeat_stamp, time_rdtime(), __ATOMIC_RELAXED);
    trigger_ssi();
}

/* Helper to initialize an idle task for a given hart. */
static void sched_init_idle(struct sched_task *idle, struct pcpu *pc, u8 prio)
{
    byte_array_set(byte_array_new((void *) idle, sizeof(*idle)), 0);
    idle->magic = TASK_MAGIC;
    idle->id = global_next_id++;
    idle->td_prio = prio;
    idle->td_base_prio = prio;
    sched_set_task_state(idle, TD_STATE_READY);
    idle->td_affinity = (i32) pc->cpuid; /* pin idle to its hart */
    idle->td_last_cpu = pc->cpuid; /* idle tasks are pinned, no migration */
    idle->td_quantum = sched_default_quantum[prio];
    idle->must_not_exit = true;
    idle->td_cleanup_queued = false;
    idle->callback = sched_idle_thread;
    list_init(&idle->sleep_list);
    list_init(&idle->kres_list);
    list_init(&idle->pi_held_mutexes);
    list_init(&idle->pi_held_futexes);
    idle->td_pi_lock = (spinlock_t) SPINLOCK_INITIALIZER;

    callout_init(&idle->td_sleep_callout);
    callout_init(&idle->td_quantum_callout);

    byte_array_set(byte_array_new((void *) &idle->td_tf, sizeof(idle->td_tf)),
                   0);
    idle->td_tf.sepc = (u64) (uptr) sched_task_entry;
    idle->td_tf.sp = (u64) (uptr) (idle->stack + TASK_STACK_SIZE);
    idle->td_tf.gp = (u64) (uptr) pc;
    idle->td_tf.sstatus = SSTATUS_SPP | SSTATUS_SPIE;
}

static void sched_task_finish(void)
{
    struct sched_task *td = get_pcpu()->curthread;
    assert(td != &global_main_task);

    sched_domain_detach(td);

    disable_interrupts();
    callout_cancel(&td->td_quantum_callout);
    get_pcpu()->preempt_deadline = U64_MAX;
    sched_set_task_state(td, TD_STATE_TERMINATING);
    enable_interrupts();
    sched_yield_trap();

    /* sched_yield_trap() only makes an SSI pending; delivery is
     * asynchronous, and a trap may return to the same task if the
     * scheduler couldn't switch on that attempt.  Keep requesting a
     * reschedule until this task is no longer current.
     */
    for (;;) {
        sched_yield_trap();
        hlt();
    }
}

static void sched_task_entry(void)
{
    struct sched_task *td = get_pcpu()->curthread;
    assert(td);
    assert(td->callback);

    td->callback(td->context);

    if (td->must_not_exit)
        crash("Infinite-loop task returned unexpectedly");

    sched_task_finish();
}

/* Allocate and initialize common task fields.
 * Returns NULL on ENOMEM.  Caller must set trapframe, callback/proc,
 * and call sched_task_enqueue() to finalize.
 */
static struct sched_task *sched_task_alloc_init(void)
{
    struct option_byte_array task_mem_opt =
        kvalloc_alloc(sizeof(struct sched_task), alignof(struct sched_task));
    if (task_mem_opt.is_none)
        return NULL;
    struct sched_task *task =
        byte_array_ptr(option_byte_array_checked(task_mem_opt));

    /* Zero metadata fields.  Skip the guard and stack regions (large, and
     * the guard page is unmapped anyway).  This avoids stale values in
     * must_not_exit, cpu_time_us, switch_in_ticks, td_starvation, etc.
     */
    byte_array_set(
        byte_array_new((byte *) task + offsetof(struct sched_task, td_tf),
                       sizeof(*task) - offsetof(struct sched_task, td_tf)),
        0);

    /* Unmap the guard page at the bottom of the stack allocation.
     * Stack overflow now triggers a page fault instead of silent corruption.
     */
    paging_unmap_page((vaddr_t) task->guard);

    task->magic = TASK_MAGIC;
    task->td_affinity = -1;
    task->td_last_cpu = U32_MAX; /* sentinel: never ran yet */
    task->td_cleanup_queued = false;

    list_init(&task->sleep_list);
    list_init(&task->kres_list);
    list_init(&task->pi_held_mutexes);
    list_init(&task->pi_held_futexes);
    task->td_pi_lock = (spinlock_t) SPINLOCK_INITIALIZER;

    callout_init(&task->td_sleep_callout);
    callout_init(&task->td_quantum_callout);

    /* Thread lifecycle defaults: kernel tasks bypass the join machinery
     * entirely (TD_JOIN_FREE). User-thread creation sets JOINABLE
     * before enqueuing.
     */
    task->td_join_state = TD_JOIN_FREE;
    task->td_exit_code = 0;
    init_waitqueue_head(&task->td_join_wq);
    task->td_exit_started = false;
    task->td_cap_slot = -1;

#if CONFIG_SCHED_DEADLINE
    sched_dl_task_init(task);
#endif

    /* gp must point to pcpu so get_pcpu() works in the new task. */
    task->td_tf.gp = (u64) (uptr) get_pcpu();

    return task;
}

/* Assign priority, allocate ID, enqueue into run queue. */
static void sched_task_enqueue(struct sched_task *task, u8 prio)
{
    /* Allocate task ID under sched_lock (protects global_next_id). */
    u64 id_flags = spin_lock_irqsave(&sched_lock);
    task->id = global_next_id++;
    spin_unlock_irqrestore(&sched_lock, id_flags);

    task->td_prio = prio;
    task->td_base_prio = prio;
    sched_set_task_state(task, TD_STATE_READY);
    task->last_activity_ms = time_current_ms().ms;
    /* Every user-created task gets a non-zero quantum for hard-RT preemption.
     * Only the per-hart idle thread (sched_init_idle) uses quantum 0.
     */
    task->td_quantum = sched_default_quantum[prio];
    if (task->td_quantum == 0)
        task->td_quantum = 1;

    sched_enqueue_ready(task);
}

/* Internal: create a task with explicit hart affinity.
 * affinity = -1 means any hart; >= 0 pins to that logical CPU.
 * noreturn = true marks the task as must-not-exit (panic if callback returns).
 */
static struct result sched_create_impl_ex(sched_callback_func_t callback,
                                          void *context,
                                          u8 prio,
                                          i32 affinity,
                                          bool noreturn)
{
    assert(global_sched_initialized);
    assert(callback);
    assert(prio < CONFIG_SCHED_NPRIO);
    assert(affinity == -1 || (affinity >= 0 && (u32) affinity < MAX_CPUS));

    struct sched_task *task = sched_task_alloc_init();
    if (!task)
        return result_error(ENOMEM);

    task->callback = callback;
    task->context = context;
    task->td_affinity = affinity;
    task->must_not_exit = noreturn;

    /* Build pre-built trapframe for the exception-return context switch.
     * When this task is first scheduled, sret restores this frame and
     * jumps to sched_task_entry with a clean register state.
     * (td_tf was already zeroed by the metadata memset above.)
     */
    task->td_tf.sepc = (u64) (uptr) sched_task_entry;
    task->td_tf.sp = (u64) (uptr) (task->stack + TASK_STACK_SIZE);

    /* SPP = return to S-mode, SPIE = enable interrupts on sret. */
    task->td_tf.sstatus = SSTATUS_SPP | SSTATUS_SPIE;

    sched_task_enqueue(task, prio);

    return result_ok();
}

struct result sched_create_task_prio(sched_callback_func_t callback,
                                     void *context,
                                     u8 prio)
{
    return sched_create_impl_ex(callback, context, prio, -1, false);
}

struct result sched_create_task(sched_callback_func_t callback, void *context)
{
    return sched_create_task_prio(callback, context, SCHED_PRIO_NORMAL);
}

struct result sched_create_task_noreturn_prio(sched_callback_func_t callback,
                                              void *context,
                                              u8 prio)
{
    return sched_create_impl_ex(callback, context, prio, -1, true);
}

struct result sched_create_task_noreturn(sched_callback_func_t callback,
                                         void *context)
{
    return sched_create_task_noreturn_prio(callback, context,
                                           SCHED_PRIO_NORMAL);
}

/* Per-thread user stack VA within the proc slot.  Thread index 0
 * (the leader) gets the top of the slot; thread N's stack occupies
 * the band immediately below thread N-1's guard page.  Each band is
 * USER_STACK_SIZE + PAGE_SIZE (one stack + one guard).
 */
static vaddr_t user_thread_stack_top(struct proc *p, u8 idx)
{
    return (vaddr_t) (p->va_stack_top -
                      (u64) idx * (USER_STACK_SIZE + PAGE_SIZE));
}

static inline i32 user_thread_cap_slot(u8 task_slot)
{
    return CAP_SPACE_SLOTS - PROC_THREAD_MAX + (i32) task_slot;
}

static void rollback_user_thread_stack(struct proc *p,
                                       ptr stack_bottom,
                                       vaddr_t stack_top_va)
{
    for (ptr va = stack_bottom; va < (ptr) stack_top_va; va += PAGE_SIZE)
        proc_unmap_user_page(p, (vaddr_t) va);
    proc_remove_vma(p, (vaddr_t) stack_bottom, USER_STACK_SIZE);
}

struct result sched_create_user_task(struct proc *p, ptr entry, u8 prio)
{
    assert(global_sched_initialized);
    assert(p);
    assert(prio < CONFIG_SCHED_NPRIO);

    /* Leader stack at the top of the per-process VA window. */
    vaddr_t stack_top_va = user_thread_stack_top(p, 0);
    ptr stack_bottom = (ptr) (stack_top_va - USER_STACK_SIZE);
    for (ptr va = stack_bottom; va < (ptr) stack_top_va; va += PAGE_SIZE) {
        struct result r = proc_map_user_page(p, va, PT_FLAG_USER | PT_FLAG_RW);
        if (r.is_error)
            return r;
    }

    /* Guard page: unmap the page immediately below the stack so overflow
     * triggers a page fault instead of silent memory corruption.
     * Verify the guard address doesn't collide with the code region to
     * avoid punching a hole in a mapped ELF segment.
     */
    vaddr_t guard_va = (vaddr_t) stack_bottom - PAGE_SIZE;
    if ((uptr) guard_va >= (uptr) p->va_code_base)
        paging_unmap_page(guard_va);

    /* Register stack VMA for user-pointer validation. */
    i32 vma_rc = proc_add_vma(p, stack_bottom, USER_STACK_SIZE,
                              VMA_PERM_READ | VMA_PERM_WRITE);
    if (vma_rc < 0)
        return result_error(ENOMEM);

    struct sched_task *task = sched_task_alloc_init();
    if (!task)
        return result_error(ENOMEM);

    task->proc = p;
    /* The leader is the first thread of the process; mark joinable so
     * pthread_join on the leader's TID has well-defined semantics.
     * Process exit triggers TD_JOIN_REAPED handling separately.
     */
    task->td_join_state = TD_JOIN_JOINABLE;

    /* Build trapframe for U-mode entry.
     * SPP = 0 (return to U-mode), SPIE = 1 (enable interrupts on sret).
     */
    task->td_tf.sepc = (u64) entry;
    task->td_tf.sp = (u64) stack_top_va;
    task->td_tf.sstatus = SSTATUS_SPIE; /* SPP=0 for U-mode */

    /* Set proc<->task link before enqueue - once enqueued, another hart
     * may schedule the task immediately. The first task in the proc
     * becomes the thread-group leader; subsequent tasks (when
     * pthread_create lands) attach into higher slots.
     *
     * On attach failure (task table full) the freshly allocated task
     * must be torn down: the guard page was unmapped during alloc, so
     * remap it before kvalloc_free or the next allocation observing the
     * same physical page would page-fault on first touch.
     */
    {
        u64 pflags = proc_table_lock_irqsave();
        bool ok = proc_attach_task(p, task);
        proc_table_unlock_irqrestore(pflags);
        if (!ok) {
            task->proc = NULL;
            paging_map_page((vaddr_t) task->guard, (paddr_t) task->guard,
                            PT_FLAG_RW);
            kvalloc_free(byte_array_new((void *) task, sizeof(*task)));
            return result_error(EAGAIN);
        }
    }

    u8 thread_slot = proc_task_slot(p, task);
    i32 thread_handle = cap_open_handle(
        p, thread_slot, CAP_TYPE_THREAD, CAP_RIGHT_READ | CAP_RIGHT_WRITE,
        user_thread_cap_slot(thread_slot), true);
    if (thread_handle < 0) {
        u64 pflags = proc_table_lock_irqsave();
        i64 token = proc_reap_exited_thread_locked(p, task);
        proc_table_unlock_irqrestore(pflags);
        if (token >= 0)
            (void) cap_drop_token(p, (u64) token);
        paging_map_page((vaddr_t) task->guard, (paddr_t) task->guard,
                        PT_FLAG_RW);
        kvalloc_free(byte_array_new((void *) task, sizeof(*task)));
        return result_error((u16) (-thread_handle));
    }
    task->td_cap_slot = (i16) thread_handle;

    sched_task_enqueue(task, prio);

    return result_ok();
}

/* Create an additional user thread inside an existing process. The
 * process must already have at least one task (the leader).  The new
 * thread runs at u_entry with u_arg in a0, on its own stack assigned
 * out of the per-process VA window.  Caller must NOT hold
 * proc_table_lock; this routine takes it internally. On any failure
 * path the proc state is unchanged.
 */
i32 sched_create_user_thread(struct proc *p,
                             ptr u_entry,
                             ptr u_arg,
                             u8 prio,
                             u32 inherited_sigmask,
                             struct sched_task **out_td)
{
    assert(global_sched_initialized);
    if (!p || !out_td)
        return -(i32) EINVAL;
    if (prio >= CONFIG_SCHED_NPRIO)
        return -(i32) EINVAL;

    u8 slot = PROC_THREAD_MAX;
    i32 reserve_rc = -(i32) EAGAIN;
    {
        u64 pflags = proc_table_lock_irqsave();
        if (proc_reserve_thread_slot(p, &slot)) {
            reserve_rc = 0;
        } else if (p->state != PROC_STATE_RUNNING || p->n_tasks == 0) {
            reserve_rc = -(i32) ESRCH;
        }
        proc_table_unlock_irqrestore(pflags);
    }
    if (slot == PROC_THREAD_MAX)
        return reserve_rc;

    vaddr_t stack_top_va = user_thread_stack_top(p, slot);
    ptr stack_bottom = (ptr) (stack_top_va - USER_STACK_SIZE);
    for (ptr va = stack_bottom; va < (ptr) stack_top_va; va += PAGE_SIZE) {
        struct result r = proc_map_user_page(p, va, PT_FLAG_USER | PT_FLAG_RW);
        if (r.is_error) {
            rollback_user_thread_stack(p, stack_bottom, stack_top_va);
            u64 pflags = proc_table_lock_irqsave();
            proc_release_thread_slot(p, slot);
            proc_table_unlock_irqrestore(pflags);
            return -(i32) r.code;
        }
    }
    vaddr_t guard_va = (vaddr_t) stack_bottom - PAGE_SIZE;
    if ((uptr) guard_va >= (uptr) p->va_code_base)
        paging_unmap_page(guard_va);

    i32 vma_rc = proc_add_vma(p, stack_bottom, USER_STACK_SIZE,
                              VMA_PERM_READ | VMA_PERM_WRITE);
    if (vma_rc < 0) {
        rollback_user_thread_stack(p, stack_bottom, stack_top_va);
        u64 pflags = proc_table_lock_irqsave();
        proc_release_thread_slot(p, slot);
        proc_table_unlock_irqrestore(pflags);
        return -(i32) ENOMEM;
    }

    struct sched_task *task = sched_task_alloc_init();
    if (!task) {
        rollback_user_thread_stack(p, stack_bottom, stack_top_va);
        u64 pflags = proc_table_lock_irqsave();
        proc_release_thread_slot(p, slot);
        proc_table_unlock_irqrestore(pflags);
        return -(i32) ENOMEM;
    }

    task->proc = p;
    task->td_tf.sepc = (u64) u_entry;
    task->td_tf.sp = (u64) stack_top_va;
    task->td_tf.a0 = (u64) u_arg;
    /* Implicit return: when the thread function returns, ra points at
     * an unmapped per-process trampoline; the resulting page fault is
     * handled in trap_dispatch by issuing SYS_THREAD_EXIT(0). Without
     * this, returning from the entry function would pop a zeroed ra
     * and fault to a different address that kills the whole process.
     */
    task->td_tf.ra = (u64) thread_exit_trampoline_pc(p);
    /* s11 (callee-saved) carries the trampoline magic so trap.c can
     * distinguish a clean implicit return from a wild-pointer jump
     * that happens to land on the trampoline PC.
     */
    task->td_tf.s11 = THREAD_EXIT_TRAMPOLINE_MAGIC;
    task->td_tf.sstatus = SSTATUS_SPIE;
    task->td_join_state = TD_JOIN_JOINABLE;
    task->td_sig.blocked = inherited_sigmask;

    {
        u64 pflags = proc_table_lock_irqsave();
        bool ok = p->state == PROC_STATE_RUNNING &&
                  proc_attach_task_slot(p, task, slot);
        if (!ok)
            proc_release_thread_slot(p, slot);
        proc_table_unlock_irqrestore(pflags);
        if (!ok) {
            task->proc = NULL;
            paging_map_page((vaddr_t) task->guard, (paddr_t) task->guard,
                            PT_FLAG_RW);
            kvalloc_free(byte_array_new((void *) task, sizeof(*task)));
            rollback_user_thread_stack(p, stack_bottom, stack_top_va);
            return -(i32) EAGAIN;
        }
    }

    i32 thread_handle = cap_open_handle(p, slot, CAP_TYPE_THREAD,
                                        CAP_RIGHT_READ | CAP_RIGHT_WRITE,
                                        user_thread_cap_slot(slot), true);
    if (thread_handle < 0) {
        u64 pflags = proc_table_lock_irqsave();
        i64 token = proc_reap_exited_thread_locked(p, task);
        proc_table_unlock_irqrestore(pflags);
        if (token >= 0)
            (void) cap_drop_token(p, (u64) token);
        paging_map_page((vaddr_t) task->guard, (paddr_t) task->guard,
                        PT_FLAG_RW);
        kvalloc_free(byte_array_new((void *) task, sizeof(*task)));
        return thread_handle;
    }
    task->td_cap_slot = (i16) thread_handle;

    sched_task_enqueue(task, prio);
    *out_td = task;
    return 0;
}

u16 sched_current_id(void)
{
    if (!global_sched_initialized)
        return 0;
    struct sched_task *td = get_pcpu()->curthread;
    if (!td)
        return 0;
    return td->id;
}

struct sched_task *sched_current_task(void)
{
    return get_pcpu()->curthread;
}

/* Sleep

 * Callout callback: wakes the sleeping task from ISR context.
 */
static void sleep_callout_cb(void *arg)
{
    struct sched_task *td = arg;

    /* Remove from global sleep list under sched_lock and transition
     * to READY before releasing, so other harts never see the task
     * as SLEEPING once it has been unlinked.
     */
    spin_lock(&sched_lock);
    if (td->state != TD_STATE_SLEEPING) {
        spin_unlock(&sched_lock);
        return;
    }
    list_del_init(&td->sleep_list);
    __atomic_store_n(&td->last_activity_ms, time_current_ms().ms,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&td->hung, false, __ATOMIC_RELAXED);
    sched_set_task_state(td, TD_STATE_READY);
    sched_note_wakeup(td);
    spin_unlock(&sched_lock);

    /* Enqueue to appropriate CPU's run queue (handles its own locking). */
    sched_enqueue_ready(td);
}

/* Force-wake a sleeping task (e.g. for signal delivery).
 * Cancels the sleep callout, removes from global_sleep_list, and
 * re-enqueues as READY.  Safe to call from any context.
 * No-op if the task is not in TD_STATE_SLEEPING.
 */
void sched_wake_sleeping(struct sched_task *td)
{
    spin_lock(&sched_lock);
    if (td->state != TD_STATE_SLEEPING) {
        spin_unlock(&sched_lock);
        return;
    }
    list_del_init(&td->sleep_list);
    sched_set_task_state(td, TD_STATE_READY);
    sched_note_wakeup(td);
    spin_unlock(&sched_lock);

    /* Synchronous cancel: the sleep callout may be mid-flight on another
     * hart.  We already transitioned td to READY under sched_lock so the
     * callback's state check will no-op, but we must wait for it to finish
     * before the caller can safely re-sleep the task or reuse the callout.
     */
    callout_cancel_sync(&td->td_sleep_callout);
    sched_enqueue_ready(td);
}

void sched_cancel_blocked(struct sched_task *task)
{
    if (!task)
        return;

    if (task->state == TD_STATE_SLEEPING) {
        sched_wake_sleeping(task);
        return;
    }

    if (task->state != TD_STATE_BLOCKED && task->state != TD_STATE_SEM_WAIT)
        return;

    if (task->td_block_cleanup) {
        sched_block_cleanup_fn_t fn = task->td_block_cleanup;
        void *ctx = task->td_block_cleanup_ctx;

        sched_clear_block_cleanup(task);
        fn(task, ctx);
    }

    if (task->state == TD_STATE_BLOCKED || task->state == TD_STATE_SEM_WAIT)
        sched_wake_ready(task);
}

void sleep_ms(struct time_ms duration)
{
    assert(global_sched_initialized);
    DEBUG_ASSERT(!in_interrupt_context());

    struct sched_task *td = get_pcpu()->curthread;

    disable_interrupts();

    /* Cancel quantum callout and disarm preemption deadline. */
    callout_cancel(&td->td_quantum_callout);
    get_pcpu()->preempt_deadline = U64_MAX;

    if (duration.ms == 0) {
        sched_set_task_state(td, TD_STATE_YIELDING);
    } else {
        sched_set_task_state(td, TD_STATE_SLEEPING);

        /* Add to global_sleep_list for sched_for_each_task iteration
         * (tracking only - wake decision comes from the callout).
         */
        u64 flags = spin_lock_irqsave(&sched_lock);
        list_add_tail(&global_sleep_list, &td->sleep_list);
        spin_unlock_irqrestore(&sched_lock, flags);

        callout_set_ticks(&td->td_sleep_callout, time_ms_to_ticks(duration.ms),
                          sleep_callout_cb, td);
    }

    enable_interrupts();
    sched_yield_trap();
}

/* Init */

void sched_init(void)
{
    assert(!global_sched_initialized);

    struct pcpu *pc = get_pcpu();

    /* Main task: the current execution context that called sched_init. */
    byte_array_set(
        byte_array_new((void *) &global_main_task, sizeof(global_main_task)),
        0);
    global_main_task.magic = TASK_MAGIC;
    global_main_task.id = global_next_id++;
    global_main_task.state = TD_STATE_RUNNING;
    global_main_task.td_prio = SCHED_PRIO_IDLE;
    global_main_task.td_base_prio = SCHED_PRIO_IDLE;
    global_main_task.td_affinity = 0; /* pin init flow to BSP */
    global_main_task.td_last_cpu = 0; /* main task starts on BSP */
    list_init(&global_main_task.sleep_list);
    list_init(&global_main_task.kres_list);
    list_init(&global_main_task.pi_held_mutexes);
    list_init(&global_main_task.pi_held_futexes);
    global_main_task.td_pi_lock = (spinlock_t) SPINLOCK_INITIALIZER;
    callout_init(&global_main_task.td_sleep_callout);
    callout_init(&global_main_task.td_quantum_callout);
    global_main_task.td_quantum = sched_default_quantum[SCHED_PRIO_IDLE];
    global_main_task.td_cleanup_queued = false;
    global_main_task.switch_in_ticks = time_rdtime();

    /* Publish curthread so trap_dispatch can find the current task. */
    pc->curthread = &global_main_task;

    list_init(&global_sleep_list);

    /* Initialize per-CPU run queues for all potential CPUs. */
    for (u32 c = 0; c < MAX_CPUS; c++) {
        for (int i = 0; i < CONFIG_SCHED_NPRIO; i++)
            list_init(&pcpu_runq[c][i]);
        pcpu_runq_bitmap[c] = 0;
        pcpu_runq_lock[c] = (spinlock_t) SPINLOCK_INITIALIZER;
    }

#if CONFIG_SCHED_DEADLINE
    sched_dl_init();
#endif

    /* BSP idle task: always-runnable fallback at lowest priority. */
    sched_init_idle(&idle_tasks[0], pc, SCHED_PRIO_IDLE);
    sched_enqueue_cpu_locked(&idle_tasks[0], 0);

    global_sched_initialized = true;
}
static void sched_init_hook(u32 lifecycle_flag __unused)
{
    sched_init();
}
INIT_TASK("sched",
          sched_init_hook,
          INIT_REQUIRES_NONE,
          INIT_ENTAILS(INITGRAPH_STAGE_SCHED),
          INIT_FLAG_PRIMARY);

/* Secondary hart scheduler entry (SMP) */

#if CONFIG_SMP
void sched_enter_secondary(void)
{
    struct pcpu *pc = get_pcpu();
    u32 cpuid = pc->cpuid;
    struct sched_task *idle = &idle_tasks[cpuid];

    lockdep_acquire(LOCK_LEVEL_SCHED);
    u64 flags = spin_lock_irqsave(&pcpu_runq_lock[cpuid]);
    sched_init_idle(idle, pc, SCHED_PRIO_IDLE);
    spin_unlock_irqrestore(&pcpu_runq_lock[cpuid], flags);
    lockdep_release(LOCK_LEVEL_SCHED);

    /* Set curthread and mark RUNNING - entering the idle loop directly
     * (not via sret), so the pre-built trapframe is unused until the
     * first context switch saves the real register state.
     */
    sched_set_task_state(idle, TD_STATE_RUNNING);
    pc->curthread = idle;
    idle->switch_in_ticks = time_rdtime();
    __atomic_store_n(&pc->idle, true, __ATOMIC_RELAXED);
    mp_set_cpu_idle(cpuid);

    /* Do NOT enable interrupts here.  Still running on the
     * interrupt stack (set by _secondary_start).  If a timer fires now,
     * _trap_entry's csrrw would reset sp to intr_stack_top, clobbering
     * the active call frame.  Interrupts are enabled inside
     * sched_idle_thread() after sched_call_on_stack has moved sp to
     * the idle task's own stack.
     */

    /* Switch to the idle task's own stack before entering the loop.
     * Secondary harts were running on intr_stack_top (set by
     * _secondary_start).  _trap_entry also uses intr_stack_top via
     * sscratch, so the hart must vacate it to avoid stack corruption.
     */
    sched_call_on_stack((u64) (uptr) (idle->stack + TASK_STACK_SIZE),
                        sched_idle_thread, NULL);
}
#endif /* CONFIG_SMP */

/* Task info iterator */

static struct sched_task_info sched_task_info_from(
    const struct sched_task *task)
{
    /* For the currently running task, include time elapsed since last
     * switch-in.
     */
    u64 cpu = task->cpu_time_us;
    if (task->state == TD_STATE_RUNNING)
        cpu += time_ticks_to_us(time_rdtime() - task->switch_in_ticks);

    return (struct sched_task_info) {
        .id = task->id,
        .state = task->state,
        .prio = task->td_prio,
        .cpu_time_us = cpu,
        .callback = task->callback,
        .last_activity_ms = task->last_activity_ms,
        .hung = task->hung,
    };
}

/* Internal: iterate every known task while holding sched_lock.
 * Visits running tasks on each hart, ready queues, and sleep list.
 * The callback receives a raw task pointer - caller must not free.
 */
typedef void (*sched_raw_task_cb_t)(struct sched_task *td, void *ctx);

static void sched_for_each_task_locked(sched_raw_task_cb_t cb, void *ctx)
{
    struct sched_task *task;

    /* Visit currently running tasks on each hart. */
    for (u32 i = 0; i < MAX_CPUS; i++) {
        if (!pcpu_array[i].online)
            continue;
        struct sched_task *td = pcpu_array[i].curthread;
        if (td)
            cb(td, ctx);
    }

    /* Visit per-CPU run queues.  Use trylock to avoid blocking if
     * another hart is in sched_schedule.  Missing a few tasks in a
     * diagnostic scan is acceptable.
     */
    for (u32 c = 0; c < MAX_CPUS; c++) {
        if (!pcpu_array[c].online)
            continue;
        bool locked = spin_trylock(&pcpu_runq_lock[c]);
        if (!locked)
            continue;
        for (int p = CONFIG_SCHED_NPRIO - 1; p >= 0; p--) {
            list_for_each_entry_safe (&pcpu_runq[c][p], task, struct sched_task,
                                      sleep_list) {
                cb(task, ctx);
            }
        }
        spin_unlock(&pcpu_runq_lock[c]);
    }

    /* Visit sleeping tasks. */
    list_for_each_entry_safe (&global_sleep_list, task, struct sched_task,
                              sleep_list) {
        cb(task, ctx);
    }
}

/* Adapter: convert raw task to info struct and forward to user callback. */
struct for_each_task_ctx {
    sched_task_iter_cb_t cb;
    void *ctx;
};

static void for_each_task_adapter(struct sched_task *td, void *raw_ctx)
{
    struct for_each_task_ctx *fctx = raw_ctx;
    fctx->cb(sched_task_info_from(td), fctx->ctx);
}

void sched_for_each_task(sched_task_iter_cb_t cb, void *ctx)
{
    assert(global_sched_initialized);
    assert(cb);

    struct for_each_task_ctx fctx = {.cb = cb, .ctx = ctx};
    u64 flags = spin_lock_irqsave(&sched_lock);
    sched_for_each_task_locked(for_each_task_adapter, &fctx);
    spin_unlock_irqrestore(&sched_lock, flags);
}

void sched_note_wakeup(struct sched_task *task)
{
    if (!task)
        return;
    task->td_wakeup_ticks = time_rdtime();
}

void sched_wake_ready(struct sched_task *task)
{
    if (!task)
        return;

    __atomic_store_n(&task->last_activity_ms, time_current_ms().ms,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&task->hung, false, __ATOMIC_RELAXED);
    sched_set_task_state(task, TD_STATE_READY);
    sched_note_wakeup(task);
    sched_enqueue_ready(task);
}

void sched_get_latency_stats(struct sched_latency_stats *out)
{
    assert(out);
    out->wakeup_latency_max_us =
        __atomic_load_n(&sched_wakeup_latency_max_us, __ATOMIC_RELAXED);
    for (u32 i = 0; i < countof(out->wakeup_latency_hist); i++) {
        out->wakeup_latency_hist[i] =
            __atomic_load_n(&sched_wakeup_latency_hist[i], __ATOMIC_RELAXED);
    }
}

void sched_get_ctxsw_stats(struct sched_ctxsw_stats *out)
{
    assert(out);
    u64 total_sw = 0, total_cycles = 0, max_cycles = 0, total_mig = 0;
    u64 total_remote = 0;
    u32 ncpus = nr_cpus_online;
    for (u32 i = 0; i < ncpus; i++) {
        struct pcpu_ctxsw_stats cs = pcpu_ctxsw_stats_get(i);
        total_sw += cs.nr_ctxsw;
        total_cycles += cs.ctxsw_cycles_total;
        if (cs.ctxsw_cycles_max > max_cycles)
            max_cycles = cs.ctxsw_cycles_max;
        total_mig += cs.nr_migrations;
        total_remote += cs.nr_remote_wakeups;
    }
    out->nr_ctxsw = total_sw;
    out->avg_cycles = total_sw > 0 ? total_cycles / total_sw : 0;
    out->max_cycles = max_cycles;
    out->nr_migrations = total_mig;
    out->nr_remote_wakeups = total_remote;
}

void sched_note_activity(void)
{
    struct pcpu *pc = get_pcpu();
    struct sched_task *td = pc->curthread;
    if (td) {
        __atomic_store_n(&td->last_activity_ms, time_current_ms().ms,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&td->hung, false, __ATOMIC_RELAXED);
    }
    /* Stamp per-hart heartbeat. Long-running hot paths still call
     * sched_note_activity() so watchdog freshness reflects useful work
     * rather than only scheduler entries.
     */
    __atomic_store_n(&pc->heartbeat_stamp, time_rdtime(), __ATOMIC_RELAXED);
}

/* Watchdog: scans all known tasks for inactivity. */

#define WATCHDOG_INTERVAL_MS 500
#define WATCHDOG_TIMEOUT_MS 5000
#define HART_WATCHDOG_TIMEOUT_MS 2000

static u32 watchdog_nr_warnings;

static void watchdog_check_task(struct sched_task *td, void *ctx)
{
    u64 now_ms = *(u64 *) ctx;
    if (td->td_prio == SCHED_PRIO_IDLE || td->last_activity_ms == 0)
        return;

    bool is_waiting =
        (td->state == TD_STATE_SLEEPING || td->state == TD_STATE_BLOCKED ||
         td->state == TD_STATE_SEM_WAIT);

    /* Clear the hung flag if the task recovered (fresh activity or now
     * legitimately waiting).  This lets the watchdog re-fire if the same
     * task hangs again later.
     */
    if (td->hung &&
        (is_waiting || now_ms - td->last_activity_ms <= WATCHDOG_TIMEOUT_MS)) {
        td->hung = false;
    }

    /* A task that is sleeping or blocked is deliberately waiting for a
     * timer or event - not hung.
     */
    if (is_waiting)
        return;

    if (!td->hung && now_ms >= td->last_activity_ms &&
        now_ms - td->last_activity_ms > WATCHDOG_TIMEOUT_MS) {
        td->hung = true;
        watchdog_nr_warnings++;
        pr_warn(STR("WATCHDOG: task id=%hu hung (last activity %lu ms "
                    "ago)\n"),
                (u32) td->id, now_ms - td->last_activity_ms);
    }
}

static void watchdog_mark_hung_locked(u64 now_ms)
{
    sched_for_each_task_locked(watchdog_check_task, &now_ms);
}

/* Per-hart heartbeat check: detect stalled harts (timer loss, lock
 * starvation, IPI wedge).  Idle harts are healthy (parked in wfi).
 * Runs on both UP and SMP builds: even a single hart can stall.
 *
 * Cross-hart timer skew: RISC-V mtime is a shared platform register,
 * so rdtime is nominally synchronized.  However, some implementations
 * have per-hart access latency or bus skew.  If the remote stamp
 * appears ahead of our local time (now < stamp), skip this sample
 * rather than computing a bogus age.  Same pattern as the wakeup-
 * latency telemetry guard in sched_schedule().
 */
static void watchdog_check_harts(void)
{
    u64 now = time_rdtime();
    u64 timeout_ticks = time_ms_to_ticks(HART_WATCHDOG_TIMEOUT_MS);
    u32 ncpus = nr_cpus_online;

    for (u32 i = 0; i < ncpus; i++) {
        struct pcpu *pc = &pcpu_array[i];
        if (!pc->online)
            continue;

        /* Idle harts are healthy: parked in wfi, waiting for work. */
        if (__atomic_load_n(&pc->idle, __ATOMIC_RELAXED)) {
            if (__atomic_load_n(&pc->heartbeat_stale, __ATOMIC_RELAXED))
                __atomic_store_n(&pc->heartbeat_stale, false, __ATOMIC_RELAXED);
            continue;
        }

        u64 stamp = __atomic_load_n(&pc->heartbeat_stamp, __ATOMIC_RELAXED);
        if (stamp == 0)
            continue; /* not yet initialized */

        /* Guard against cross-hart rdtime skew: if the remote stamp
         * appears in the future from our perspective, skip this sample.
         * Stale detection defers to the next watchdog pass.
         */
        if (now < stamp)
            continue;

        u64 age = now - stamp;
        if (age > timeout_ticks) {
            if (!__atomic_load_n(&pc->heartbeat_stale, __ATOMIC_RELAXED)) {
                __atomic_store_n(&pc->heartbeat_stale, true, __ATOMIC_RELAXED);
                u64 age_us = time_ticks_to_us(age);
                KTRACE("event=hart_stale hart=%u age_us=%lu", i, age_us);
                pr_warn(STR("WATCHDOG: hart %u stale (heartbeat %lu us "
                            "ago)\n"),
                        i, age_us);
            }
        } else if (__atomic_load_n(&pc->heartbeat_stale, __ATOMIC_RELAXED)) {
            __atomic_store_n(&pc->heartbeat_stale, false, __ATOMIC_RELAXED);
        }
    }
}

static void sched_watchdog_thread(void *ctx __unused)
{
    while (true) {
        sleep_ms(time_ms_new(WATCHDOG_INTERVAL_MS));

        u64 now_ms = time_current_ms().ms;
        u64 flags = spin_lock_irqsave(&sched_lock);
        watchdog_mark_hung_locked(now_ms);
        spin_unlock_irqrestore(&sched_lock, flags);

        watchdog_check_harts();
    }
}

static void sched_watchdog_init(u32 lifecycle_flag __unused)
{
    struct result r = sched_create_task_noreturn_prio(sched_watchdog_thread,
                                                      NULL, SCHED_PRIO_IDLE);
    if (r.is_error)
        pr_warn(STR("watchdog: failed to create task\n"));
}
INIT_TASK("watchdog",
          sched_watchdog_init,
          INIT_REQUIRES(INITGRAPH_STAGE_SCHED),
          INIT_ENTAILS(INITGRAPH_STAGE_SUBSYS),
          INIT_FLAG_PRIMARY);

static void watchdog_count_hung(struct sched_task *td, void *ctx)
{
    u32 *count = ctx;
    if (td->hung)
        (*count)++;
}

void sched_get_watchdog_stats(struct sched_watchdog_stats *out)
{
    assert(out);
    out->nr_warnings = __atomic_load_n(&watchdog_nr_warnings, __ATOMIC_RELAXED);

    u32 nr_hung = 0;
    u64 flags = spin_lock_irqsave(&sched_lock);
    sched_for_each_task_locked(watchdog_count_hung, &nr_hung);
    spin_unlock_irqrestore(&sched_lock, flags);

    out->nr_hung = nr_hung;
}

int sched_get_hart_watchdog(u32 cpu, struct sched_hart_watchdog_stats *out)
{
    if (cpu >= MAX_CPUS || !out)
        return -1;
    struct pcpu *pc = &pcpu_array[cpu];
    if (!pc->online) {
        *out = (struct sched_hart_watchdog_stats) {0};
        return 0;
    }
    u64 now = time_rdtime();
    u64 stamp = __atomic_load_n(&pc->heartbeat_stamp, __ATOMIC_RELAXED);
    /* Guard against cross-hart rdtime skew: if the remote stamp is
     * ahead of our local time, report age as zero (no stale inference).
     */
    u64 age = (stamp != 0 && now >= stamp) ? (now - stamp) : 0;
    out->heartbeat_age_us = time_ticks_to_us(age);
    out->stale = __atomic_load_n(&pc->heartbeat_stale, __ATOMIC_RELAXED);
    out->idle = __atomic_load_n(&pc->idle, __ATOMIC_RELAXED);
    return 0;
}

/* Named kernel domains: initialized at boot, used for built-in task
 * groups (web stack, system tasks).  Budget values chosen to prevent
 * a runaway web handler from starving system tasks:
 * - WEB: 80ms per 100ms period (80% CPU budget)
 * - SYS: 20ms per 100ms period (20% CPU budget, higher priority)
 */
static struct sched_domain kernel_domains[SCHED_DOMAIN_COUNT];
static bool kernel_domains_initialized;

static void sched_domains_boot_init(u32 lifecycle_flag __unused)
{
    sched_domain_init(&kernel_domains[SCHED_DOMAIN_WEB], time_ms_to_ticks(80),
                      time_ms_to_ticks(100));
    sched_domain_init(&kernel_domains[SCHED_DOMAIN_SYS], time_ms_to_ticks(20),
                      time_ms_to_ticks(100));
    kernel_domains_initialized = true;
}
INIT_TASK("sched_domains",
          sched_domains_boot_init,
          INIT_REQUIRES(INITGRAPH_STAGE_SCHED),
          INIT_ENTAILS(INITGRAPH_STAGE_SUBSYS),
          INIT_FLAG_PRIMARY);

struct sched_domain *sched_get_kernel_domain(u32 domain_id)
{
    if (!kernel_domains_initialized || domain_id >= SCHED_DOMAIN_COUNT)
        return NULL;
    return &kernel_domains[domain_id];
}

int sched_domain_get_stats(u32 domain_id, struct sched_domain_stats *out)
{
    if (!kernel_domains_initialized || domain_id >= SCHED_DOMAIN_COUNT || !out)
        return -1;
    struct sched_domain *dom = &kernel_domains[domain_id];
    out->quantum_ticks = dom->quantum_ticks;
    out->period_ticks = dom->period_ticks;
    out->consumed_ticks =
        __atomic_load_n(&dom->consumed_ticks, __ATOMIC_RELAXED);
    out->nr_members = dom->nr_members;
    out->state = (u32) __atomic_load_n(&dom->state, __ATOMIC_RELAXED);
    return 0;
}

/* Scheduling domains: CPU budget enforcement per task group.
 *
 * A domain tracks consumed_ticks (charged on context switch) against
 * a quantum_ticks budget per period_ticks cycle.  When the budget is
 * exhausted, the domain transitions to DEPLETED: member tasks are not
 * re-enqueued after yielding/preemption until the refill callout fires.
 *
 * Depletion is "lazy": tasks currently in run queues remain there but
 * won't be re-enqueued after their current slice.  The running task
 * finishes its current context-switch normally.  Budget overshoot is
 * bounded by one quantum (each task runs at most one quantum).
 */

/* Remove 'task' from 'dom->members[]' using swap-with-last.
 * Caller must hold sched_lock.
 */
static void domain_remove_member(struct sched_domain *dom,
                                 struct sched_task *task)
{
    for (u32 i = 0; i < dom->nr_members; i++) {
        if (dom->members[i] == task) {
            dom->members[i] = dom->members[dom->nr_members - 1];
            dom->members[dom->nr_members - 1] = NULL;
            dom->nr_members--;
            return;
        }
    }
}

static void sched_domain_refill_cb(void *arg)
{
    struct sched_domain *dom = arg;

    __atomic_store_n(&dom->consumed_ticks, 0, __ATOMIC_RELAXED);
    /* RELEASE: ensures consumed_ticks=0 is visible before ACTIVE,
     * so budget-check paths using ACQUIRE on state see consistent values.
     */
    __atomic_store_n(&dom->state, DOMAIN_ACTIVE, __ATOMIC_RELEASE);
    dom->next_refill += dom->period_ticks;

#if CONFIG_MIXED_CRIT
    if (dom->criticality == SCHED_DOMAIN_CRIT_HI)
        sched_mc_check_recovery(dom);
#endif

    /* Re-arm for the next period. */
    callout_set_ticks(&dom->refill_callout, dom->period_ticks,
                      sched_domain_refill_cb, dom);

    /* Re-enqueue members that were blocked by depletion.
     * Only re-enqueue tasks that are in BLOCKED state and belong
     * to this domain.  Tasks that terminated or are sleeping stay
     * in their current state.
     */
    u32 nr_requeued = 0;
    u64 flags = spin_lock_irqsave(&sched_lock);
    for (u32 i = 0; i < dom->nr_members; i++) {
        struct sched_task *t = dom->members[i];
        if (!t || t->state != TD_STATE_BLOCKED || t->domain != dom)
            continue;
        if (t->sleep_list.next != &t->sleep_list)
            continue;
        sched_set_task_state(t, TD_STATE_READY);
        sched_enqueue_ready(t);
        nr_requeued++;
    }
    spin_unlock_irqrestore(&sched_lock, flags);

    KTRACE("event=domain_refill quantum=%lu nr_requeued=%u", dom->quantum_ticks,
           nr_requeued);
}

void sched_domain_init(struct sched_domain *dom,
                       u64 quantum_ticks,
                       u64 period_ticks)
{
    memset(dom, 0, sizeof(*dom));
    dom->quantum_ticks = quantum_ticks;
    dom->period_ticks = period_ticks;
    dom->next_refill = time_rdtime() + period_ticks;
    callout_init(&dom->refill_callout);

    /* Arm the first refill callout. */
    callout_set_ticks(&dom->refill_callout, period_ticks,
                      sched_domain_refill_cb, dom);
}

int sched_domain_attach(struct sched_domain *dom, struct sched_task *task)
{
    if (!dom || !task)
        return -1;

    u64 flags = spin_lock_irqsave(&sched_lock);

    /* Check capacity before detaching from old domain to avoid
     * leaving the task orphaned on failure.
     */
    if (task->domain != dom && dom->nr_members >= SCHED_DOMAIN_MAX_MEMBERS) {
        spin_unlock_irqrestore(&sched_lock, flags);
        return -1;
    }

    if (task->domain)
        domain_remove_member(task->domain, task);

    dom->members[dom->nr_members++] = task;
    task->domain = dom;
    spin_unlock_irqrestore(&sched_lock, flags);
    return 0;
}

void sched_domain_detach(struct sched_task *task)
{
    u64 flags = spin_lock_irqsave(&sched_lock);
    struct sched_domain *dom = task->domain;
    if (!dom) {
        spin_unlock_irqrestore(&sched_lock, flags);
        return;
    }

    domain_remove_member(dom, task);
    task->domain = NULL;

    bool needs_wake = (task->state == TD_STATE_BLOCKED &&
                       task->sleep_list.next == &task->sleep_list);
    if (needs_wake) {
        __atomic_store_n(&task->last_activity_ms, time_current_ms().ms,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&task->hung, false, __ATOMIC_RELAXED);
        sched_set_task_state(task, TD_STATE_READY);
        sched_note_wakeup(task);
    }
    spin_unlock_irqrestore(&sched_lock, flags);

    if (needs_wake)
        sched_enqueue_ready(task);
}

/* Load balancer: periodically migrates tasks from the busiest CPU to
 * the idlest.  Runs on BSP (hart 0) every LOADBAL_INTERVAL_MS.
 *
 * Uses exponential-decay per-task load estimation (managarm-inspired):
 * each task's load_avg is updated on context switch via
 * sched_update_load_avg().  Per-hart hart_load is the sum of task
 * load_avg values on that hart.  Migration occurs when moving a task
 * reduces the max load across harts.
 */

#if CONFIG_SMP
#define LOADBAL_INTERVAL_MS 100

/* Fixed-point Q16 scale factor for load estimation. */
#define LOAD_SCALE (1ULL << 16)

/* Update a task's exponential-decay load average.  Called on context
 * switch for the outgoing task.  The task's load decays by 7/8 per
 * switch and grows by delta_running / quantum toward LOAD_SCALE.
 *
 * Simple formula: load_avg = (7 * load_avg + running_fraction) / 8
 * where running_fraction = LOAD_SCALE if the task used its full
 * quantum, 0 if it yielded immediately.
 */
static void sched_update_load_avg(struct sched_task *task, u64 delta_ticks)
{
    u64 quantum_ticks = time_ms_to_ticks(10); /* base quantum ~10ms */
    u64 running;
    if (quantum_ticks == 0 || delta_ticks >= quantum_ticks)
        running = LOAD_SCALE;
    else
        running = (delta_ticks * LOAD_SCALE) / quantum_ticks;

    /* Exponential moving average: 7/8 decay + 1/8 new sample. */
    task->load_avg = (7 * task->load_avg + running) / 8;
}

/* Apply decay for time spent sleeping/blocked.  Called when a task
 * transitions from SLEEPING/BLOCKED to READY.  For each elapsed
 * quantum of sleep, apply one round of 7/8 decay (sample = 0).
 * Capped at 8 rounds to avoid O(N) loops on long sleeps.
 */
static void sched_decay_sleeping_load(struct sched_task *task)
{
    if (task->load_avg == 0)
        return;

    u64 quantum_ticks = time_ms_to_ticks(10);
    if (quantum_ticks == 0)
        return;

    u64 now = time_rdtime();
    u64 sleep_ticks =
        (now > task->switch_in_ticks) ? now - task->switch_in_ticks : 0;
    u64 elapsed_quanta = sleep_ticks / quantum_ticks;

    /* Cap decay rounds to prevent O(N) loop on very long sleeps.
     * 8 rounds of 7/8 decay reduces load to ~34% which is sufficient
     * for the balancer to stop treating the task as CPU-heavy.
     */
    if (elapsed_quanta > 8)
        elapsed_quanta = 8;

    for (u64 i = 0; i < elapsed_quanta; i++)
        task->load_avg = (7 * task->load_avg) / 8;
}

/* Compute per-hart load as sum of task load_avg values on that hart's
 * run queue.  Caller holds pcpu_runq_lock[cpu].
 */
static u64 sched_hart_load_locked(u32 cpu)
{
    u64 load = 0;
    struct sched_task *task;
    for (int p = CONFIG_SCHED_NPRIO - 1; p >= 0; p--) {
        list_for_each_entry_safe (&pcpu_runq[cpu][p], task, struct sched_task,
                                  sleep_list) {
            load += task->load_avg;
        }
    }
    /* Include the currently running task's load. */
    struct sched_task *cur = pcpu_array[cpu].curthread;
    if (cur)
        load += cur->load_avg;
    return load;
}

static void sched_load_balance(void *ctx __unused)
{
    struct sched_task *task;

    while (true) {
        sleep_ms(time_ms_new(LOADBAL_INTERVAL_MS));

        u32 ncpus = nr_cpus_online;
        if (ncpus < 2)
            continue;

        /* Snapshot per-hart load estimates.  Use trylock to avoid
         * blocking if another hart is in sched_schedule.
         */
        u32 busiest_cpu = 0, idlest_cpu = 0;
        u64 max_load = 0, min_load = U64_MAX;

        for (u32 i = 0; i < ncpus; i++) {
            if (!pcpu_array[i].online)
                continue;
            if (!spin_trylock(&pcpu_runq_lock[i]))
                continue;
            u64 load = sched_hart_load_locked(i);
            pcpu_array[i].hart_load = load;
            spin_unlock(&pcpu_runq_lock[i]);

            if (load > max_load) {
                max_load = load;
                busiest_cpu = i;
            }
            if (load < min_load) {
                min_load = load;
                idlest_cpu = i;
            }
        }

        /* Migrate when moving a task reduces max load: only if
         * busiest has significantly more load than idlest.
         * Threshold: busiest_load - task_load > idlest_load.
         */
        if (max_load < LOAD_SCALE || max_load < min_load + LOAD_SCALE / 2)
            continue;
        if (busiest_cpu == idlest_cpu)
            continue;

        /* Lock busiest CPU and steal one migratable task with the
         * highest load_avg (most impactful migration).
         */
        lockdep_acquire(LOCK_LEVEL_SCHED);
        u64 flags = spin_lock_irqsave(&pcpu_runq_lock[busiest_cpu]);
        struct sched_task *victim = NULL;
        u64 victim_load = 0;
        for (int p = SCHED_PRIO_NORMAL; p < CONFIG_SCHED_NPRIO; p++) {
            list_for_each_entry_safe (&pcpu_runq[busiest_cpu][p], task,
                                      struct sched_task, sleep_list) {
                if (__atomic_load_n(&task->td_affinity, __ATOMIC_RELAXED) >= 0)
                    continue;
                /* Pick the task whose migration reduces max_load the most,
                 * without inverting the imbalance (busiest must still be
                 * heavier than idlest after migration).
                 */
                if (task->load_avg > victim_load &&
                    max_load - task->load_avg >= min_load + task->load_avg) {
                    victim = task;
                    victim_load = task->load_avg;
                }
            }
        }
        if (victim) {
            list_del_init(&victim->sleep_list);
            if (list_empty(&pcpu_runq[busiest_cpu][victim->td_prio]))
                pcpu_runq_bitmap[busiest_cpu] &= ~BIT(victim->td_prio);
        }
        spin_unlock_irqrestore(&pcpu_runq_lock[busiest_cpu], flags);
        lockdep_release(LOCK_LEVEL_SCHED);

        if (victim) {
            /* Enqueue to idlest CPU and wake it. */
            lockdep_acquire(LOCK_LEVEL_SCHED);
            flags = spin_lock_irqsave(&pcpu_runq_lock[idlest_cpu]);
            sched_enqueue_cpu_locked(victim, idlest_cpu);
            spin_unlock_irqrestore(&pcpu_runq_lock[idlest_cpu], flags);
            lockdep_release(LOCK_LEVEL_SCHED);
        }
    }
}

static void sched_load_balance_init(u32 lifecycle_flag __unused)
{
    struct result r = sched_create_task_noreturn_prio(sched_load_balance, NULL,
                                                      SCHED_PRIO_IDLE);
    if (r.is_error)
        pr_warn(STR("loadbal: failed to create task\n"));
}
INIT_TASK("loadbal",
          sched_load_balance_init,
          INIT_REQUIRES(INITGRAPH_STAGE_SCHED),
          INIT_ENTAILS(INITGRAPH_STAGE_SUBSYS),
          INIT_FLAG_PRIMARY);
#endif /* CONFIG_SMP */

/* Scheduler invariant checker (6a, formal-os inspired).
 *
 * Debug-only assertions called at the end of sched_schedule() to catch
 * state corruption before it propagates.  Zero cost in release builds.
 *
 * Properties verified (sotOS TLA+ scheduler spec):
 * - MutualExclusion: each hart runs at most one thread in TD_STATE_RUNNING.
 * - SingleExecution: no thread runs on more than one hart simultaneously.
 * - QueueConsistency: every thread in a run queue is in TD_STATE_READY.
 * - No TD_STATE_TERMINATING task appears in any run queue.
 * - Per-CPU runq_bitmap matches actual queue occupancy.
 */
#if __DEBUG__ > 0
static void sched_check_invariants(struct sched_task *next, u32 cpuid)
{
    struct sched_task *task;

    /* 1. curthread->state must be RUNNING on this hart. */
    DEBUG_ASSERT(next->state == TD_STATE_RUNNING);
    MAGIC_CHECK(next, TASK_MAGIC);

    /* 2. SingleExecution: no other hart should run the same task.
     * Only pointer identity is checked, not remote state - remote harts
     * may be mid-context-switch with transient non-RUNNING curthread.
     */
    for (u32 i = 0; i < MAX_CPUS; i++) {
        if (i == cpuid || !pcpu_array[i].online)
            continue;
        struct sched_task *ct = pcpu_array[i].curthread;
        DEBUG_ASSERT(ct != next);
    }

    /* 3. QueueConsistency + bitmap match on local CPU.
     * Use trylock to avoid deadlock; skip if contended.
     */
    if (spin_trylock(&pcpu_runq_lock[cpuid])) {
        u32 expected_bitmap = 0;
        for (int p = 0; p < CONFIG_SCHED_NPRIO; p++) {
            bool has_tasks = !list_empty(&pcpu_runq[cpuid][p]);
            if (has_tasks)
                expected_bitmap |= BIT(p);

            /* Every task in a run queue must be READY, not
             * RUNNING/TERMINATING/BLOCKED.
             */
            list_for_each_entry_safe (&pcpu_runq[cpuid][p], task,
                                      struct sched_task, sleep_list) {
                MAGIC_CHECK(task, TASK_MAGIC);
                DEBUG_ASSERT(task->state == TD_STATE_READY);
            }
        }
        /* Bitmap must match actual queue occupancy. */
        DEBUG_ASSERT(pcpu_runq_bitmap[cpuid] == expected_bitmap);
        spin_unlock(&pcpu_runq_lock[cpuid]);
    }
}
#endif /* __DEBUG__ > 0 */

/* Self-tests */

#include __INC_TEST(sched)
#include __INC_TEST(lockdep)
#include __INC_TEST(tls)
