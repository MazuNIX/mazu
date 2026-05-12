/* SPDX-License-Identifier: MIT */
/* Process table management.
 *
 * Process lifecycle: FREE -> EMBRYO (alloc) -> RUNNING (activated) ->
 * ZOMBIE (exit) -> FREE (reaped by parent or auto-reaped).
 * SLEEPING and STOPPED are intermediate states for I/O and signals.
 */

#include <mazu/assert.h>
#include <mazu/cap.h>
#include <mazu/eventlog.h>
#include <mazu/kvalloc.h>
#include <mazu/paging.h>
#include <mazu/print.h>
#include <mazu/proc.h>
#include <mazu/sched.h>
#include <mazu/string.h>
#include <mazu/time.h>
#include <mazu/uaccess.h>

#include "../lockdep.h"
#include "../sched/waitqueue.h"
#include "../sync/futex.h"
#include "../sync/sync_handle.h"
#include "../timer/posix_timer.h"
static struct proc proc_table[PROC_MAX];
spinlock_t proc_table_lock = SPINLOCK_INITIALIZER;
static u16 next_pid = 1;

/* Per-process child wait queues: parent blocks here until a child
 * enters ZOMBIE.  Indexed by proc_table slot, not by PID.
 */
static struct wait_queue_head child_wqs[PROC_MAX];

static sz proc_slot(struct proc *p)
{
    DEBUG_ASSERT(p >= &proc_table[0] && p < &proc_table[PROC_MAX]);
    return (sz) (p - proc_table);
}

static bool proc_child_matches_parent(const struct proc *child,
                                      const struct proc *parent)
{
    return child && parent && child != parent &&
           child->parent_pid == parent->pid &&
           child->parent_generation == parent->generation;
}

static vaddr_t proc_thread_stack_top(const struct proc *p, u8 slot)
{
    return (vaddr_t) (p->va_stack_top -
                      (u64) slot * (USER_STACK_SIZE + PAGE_SIZE));
}

static i32 proc_detach_thread_cap_slot_locked(struct sched_task *td)
{
    if (!td || td->td_cap_slot < 0)
        return -1;

    i32 slot = td->td_cap_slot;
    td->td_cap_slot = -1;
    return slot;
}

u64 proc_table_lock_irqsave(void)
{
    lockdep_acquire(LOCK_LEVEL_PROC);
    return spin_lock_irqsave(&proc_table_lock);
}

void proc_table_unlock_irqrestore(u64 flags)
{
    spin_unlock_irqrestore(&proc_table_lock, flags);
    lockdep_release(LOCK_LEVEL_PROC);
}

u64 proc_fd_lock_irqsave(struct proc *p)
{
    assert(p);
    lockdep_acquire(LOCK_LEVEL_FD);
    return spin_lock_irqsave(&p->fd_lock);
}

void proc_fd_unlock_irqrestore(struct proc *p, u64 flags)
{
    assert(p);
    spin_unlock_irqrestore(&p->fd_lock, flags);
    lockdep_release(LOCK_LEVEL_FD);
}

u64 proc_sig_lock_irqsave(struct proc *p)
{
    assert(p);
    lockdep_acquire(LOCK_LEVEL_SIG);
    return spin_lock_irqsave(&p->sig_lock);
}

void proc_sig_unlock_irqrestore(struct proc *p, u64 flags)
{
    assert(p);
    spin_unlock_irqrestore(&p->sig_lock, flags);
    lockdep_release(LOCK_LEVEL_SIG);
}

static u16 proc_alloc_pid_locked(void)
{
    for (u32 attempts = 0; attempts < U16_MAX; attempts++) {
        if (next_pid == 0)
            next_pid = 1; /* PID 0 is reserved/invalid. */
        u16 pid = next_pid++;
        bool in_use = false;
        for (sz i = 0; i < PROC_MAX; i++) {
            if (proc_table[i].state != PROC_STATE_FREE &&
                proc_table[i].pid == pid) {
                in_use = true;
                break;
            }
        }
        if (!in_use)
            return pid;
    }
    return 0;
}

static void proc_free_locked(struct proc *p)
{
    MAGIC_CHECK(p, PROC_MAGIC);
    DEBUG_ASSERT(p->state == PROC_STATE_ZOMBIE ||
                 p->state == PROC_STATE_EMBRYO);

    proc_free_user_pages(p);

    cap_space_teardown(p);

    p->n_vmas = 0;
    p->generation++;
    p->magic = 0xDEADDEADU; /* poison for use-after-free detection */
    p->state = PROC_STATE_FREE;
}

void proc_init(void)
{
    memset(proc_table, 0, sizeof(proc_table));
    proc_table_lock = (spinlock_t) SPINLOCK_INITIALIZER;
    next_pid = 1;
    cap_init();
    for (sz i = 0; i < PROC_MAX; i++) {
        init_waitqueue_head(&child_wqs[i]);
        init_waitqueue_head(&proc_table[i].thread_event_wq);
    }
}

void proc_set_state(struct proc *p, enum proc_state new_state)
{
    assert(p);
    MAGIC_CHECK(p, PROC_MAGIC);
#if __DEBUG__
    /* Valid state transitions encoded as a bitmask per source state. */
    static const u8 valid_transitions[] = {
        [PROC_STATE_FREE] = BIT(PROC_STATE_EMBRYO),
        [PROC_STATE_EMBRYO] = BIT(PROC_STATE_RUNNING) | BIT(PROC_STATE_FREE),
        [PROC_STATE_RUNNING] = BIT(PROC_STATE_SLEEPING) |
                               BIT(PROC_STATE_STOPPED) | BIT(PROC_STATE_ZOMBIE),
        [PROC_STATE_SLEEPING] =
            BIT(PROC_STATE_RUNNING) | BIT(PROC_STATE_ZOMBIE),
        [PROC_STATE_STOPPED] = BIT(PROC_STATE_RUNNING) | BIT(PROC_STATE_ZOMBIE),
        [PROC_STATE_ZOMBIE] = BIT(PROC_STATE_FREE),
    };
    DEBUG_ASSERT(valid_transitions[p->state] & BIT(new_state));
#endif
    p->state = new_state;
}

struct proc *proc_alloc(void)
{
    u64 flags = proc_table_lock_irqsave();
    for (sz i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].state == PROC_STATE_FREE) {
            struct proc *p = &proc_table[i];
            u32 gen = p->generation;
            u16 pid = proc_alloc_pid_locked();
            if (pid == 0) {
                proc_table_unlock_irqrestore(flags);
                return NULL;
            }
            memset(p, 0, sizeof(*p));
            p->generation = gen;
            p->magic = PROC_MAGIC;
            p->pid = pid;
            p->state = PROC_STATE_EMBRYO;
            p->leader_idx = PROC_THREAD_MAX;
            p->vma_cache_read = PROC_VMA_MAX;
            p->vma_cache_write = PROC_VMA_MAX;
            p->watchdog_heartbeat_ms = time_current_ms().ms;
            p->fd_lock = (spinlock_t) SPINLOCK_INITIALIZER;
            p->sig_lock = (spinlock_t) SPINLOCK_INITIALIZER;
            init_waitqueue_head(&p->thread_event_wq);
            p->cwd[0] = '/';
            p->cwd_len = 1;
            /* Assign per-process VA window based on table slot index.
             * Each slot gets PROC_SLOT_SIZE bytes of virtual address
             * space so concurrent processes never overlap.
             */
            p->va_code_base = (vaddr_t) (USER_CODE_BASE + i * PROC_SLOT_SIZE);
            p->va_stack_top =
                (vaddr_t) (USER_CODE_BASE + (i + 1) * PROC_SLOT_SIZE);
            /* Re-initialize the child wait queue for this slot.
             * Ensures a clean list head regardless of prior state.
             */
            init_waitqueue_head(&child_wqs[i]);
            cap_space_init(p);
            proc_table_unlock_irqrestore(flags);
            return p;
        }
    }
    proc_table_unlock_irqrestore(flags);
    return NULL;
}

bool proc_attach_task(struct proc *p, struct sched_task *td)
{
    assert(p);
    assert(td);
    if (p->n_tasks >= PROC_THREAD_MAX)
        return false;
    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        if (proc_attach_task_slot(p, td, i))
            return true;
    }
    /* n_tasks said there is space but no attachable slot found:
     * invariant broken.
     */
    DEBUG_ASSERT(false);
    return false;
}

bool proc_attach_task_slot(struct proc *p, struct sched_task *td, u8 slot)
{
    assert(p);
    assert(td);
    if (slot >= PROC_THREAD_MAX)
        return false;
    if (p->n_tasks >= PROC_THREAD_MAX)
        return false;
    if (p->tasks[slot])
        return false;
    if (!(p->reserved_task_slots & BIT(slot)) && p->n_tasks != 0)
        return false;

    p->reserved_task_slots &= (u8) ~BIT(slot);
    p->tasks[slot] = td;
    if (p->n_tasks == 0)
        p->leader_idx = slot;
    p->n_tasks++;
    return true;
}

bool proc_reserve_thread_slot(struct proc *p, u8 *out_slot)
{
    assert(p);
    if (!out_slot)
        return false;
    if (p->state != PROC_STATE_RUNNING)
        return false;
    if (p->n_tasks == 0)
        return false;

    u8 used = p->reserved_task_slots;
    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        if (p->tasks[i])
            used |= BIT(i);
    }
    if (used == (u8) ((1U << PROC_THREAD_MAX) - 1U))
        return false;

    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        if (!(used & BIT(i))) {
            p->reserved_task_slots |= BIT(i);
            *out_slot = i;
            return true;
        }
    }
    DEBUG_ASSERT(false);
    return false;
}

void proc_release_thread_slot(struct proc *p, u8 slot)
{
    assert(p);
    if (slot >= PROC_THREAD_MAX)
        return;
    p->reserved_task_slots &= (u8) ~BIT(slot);
}

void proc_detach_task(struct proc *p, struct sched_task *td)
{
    assert(p);
    if (!td)
        return;
    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        if (p->tasks[i] == td) {
            p->tasks[i] = NULL;
            if (p->n_tasks > 0)
                p->n_tasks--;
            if (p->n_tasks == 0) {
                p->leader_idx = PROC_THREAD_MAX;
            } else if (p->leader_idx == i) {
                for (u8 j = 0; j < PROC_THREAD_MAX; j++) {
                    if (p->tasks[j]) {
                        p->leader_idx = j;
                        break;
                    }
                }
            }
            td->proc = NULL;
            return;
        }
    }
}

void proc_release_thread_stack(struct proc *p, u8 slot)
{
    assert(p);
    if (slot >= PROC_THREAD_MAX)
        return;

    vaddr_t stack_top = proc_thread_stack_top(p, slot);
    vaddr_t stack_bottom = stack_top - (vaddr_t) USER_STACK_SIZE;

    for (vaddr_t va = stack_bottom; va < stack_top; va += PAGE_SIZE)
        proc_unmap_user_page(p, va);
    proc_remove_vma(p, stack_bottom, USER_STACK_SIZE);
}

static void proc_drop_thread_token(struct proc *p, i64 token)
{
    assert(p);
    if (token < 0)
        return;

    (void) cap_drop_token(p, (u64) token);
}

i64 proc_reap_exited_thread_locked(struct proc *p, struct sched_task *td)
{
    assert(p);
    if (!td)
        return -1;

    i64 token = -1;
    u8 slot = proc_task_slot(p, td);
    if (slot < PROC_THREAD_MAX) {
        i32 cap_slot = proc_detach_thread_cap_slot_locked(td);
        if (cap_slot >= 0) {
            struct cap_slot_view cap_slot_view = cap_slot_read(p, cap_slot);
            if (cap_slot_view.valid && cap_slot_view.type == CAP_TYPE_THREAD)
                token = (i64) cap_make_handle(&cap_slot_view);
        }
        p->exited_cpu_time_us += td->cpu_time_us;
        proc_release_thread_stack(p, slot);
        proc_detach_task(p, td);
    }
    return token;
}

void proc_reap_exited_thread(struct proc *p, struct sched_task *td)
{
    assert(p);
    if (!td)
        return;

    u64 pflags = proc_table_lock_irqsave();
    i64 token = proc_reap_exited_thread_locked(p, td);
    proc_table_unlock_irqrestore(pflags);
    proc_drop_thread_token(p, token);
}

void proc_close_fd_locked(struct proc *p, i32 fd)
{
    assert(p);
    assert(fd >= 0 && fd < PROC_FD_MAX);
    (void) cap_close_fd(p, fd);
}

void proc_close_fd(struct proc *p, i32 fd)
{
    (void) cap_close_fd(p, fd);
}

void proc_free(struct proc *p)
{
    assert(p);
    u64 flags = proc_table_lock_irqsave();
    proc_free_locked(p);
    proc_table_unlock_irqrestore(flags);
}

struct proc *proc_find_locked(u16 pid)
{
    for (sz i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].state != PROC_STATE_FREE && proc_table[i].pid == pid)
            return &proc_table[i];
    }
    return NULL;
}

struct proc *proc_find(u16 pid)
{
    u64 flags = proc_table_lock_irqsave();
    struct proc *p = proc_find_locked(pid);
    proc_table_unlock_irqrestore(flags);
    return p;
}

sz proc_collect_descendants_locked(struct proc *root,
                                   u32 root_generation,
                                   struct proc **out,
                                   u32 *out_generations,
                                   sz max)
{
    if (!root || !out || !out_generations || max == 0)
        return 0;

    if (root->state == PROC_STATE_FREE || root->generation != root_generation)
        return 0;

    sz count = 0;
    out[count] = root;
    out_generations[count] = root->generation;
    count++;

    bool added = true;
    while (added && count < max) {
        added = false;
        for (sz i = 0; i < PROC_MAX && count < max; i++) {
            struct proc *candidate = &proc_table[i];
            if (candidate->state == PROC_STATE_FREE)
                continue;

            bool is_descendant = false;
            for (sz j = 0; j < count; j++) {
                if (proc_child_matches_parent(candidate, out[j])) {
                    is_descendant = true;
                    break;
                }
            }
            if (!is_descendant)
                continue;

            bool already_listed = false;
            for (sz j = 0; j < count; j++) {
                if (out[j] == candidate) {
                    already_listed = true;
                    break;
                }
            }
            if (already_listed)
                continue;

            out[count] = candidate;
            out_generations[count] = candidate->generation;
            count++;
            added = true;
        }
    }
    return count;
}

sz proc_collect_descendants(struct proc *root,
                            u32 root_generation,
                            struct proc **out,
                            u32 *out_generations,
                            sz max)
{
    u64 flags = proc_table_lock_irqsave();
    sz count = proc_collect_descendants_locked(root, root_generation, out,
                                               out_generations, max);
    proc_table_unlock_irqrestore(flags);
    return count;
}

void proc_for_each(proc_iter_cb_t cb, void *ctx)
{
    u64 flags = proc_table_lock_irqsave();
    for (sz i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].state != PROC_STATE_FREE)
            cb(&proc_table[i], ctx);
    }
    proc_table_unlock_irqrestore(flags);
}

static bool has_zombie_child_locked(struct proc *parent)
{
    for (sz i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].state == PROC_STATE_ZOMBIE &&
            proc_child_matches_parent(&proc_table[i], parent))
            return true;
    }
    return false;
}

/* Check if parent has any non-FREE child (any state including ZOMBIE). */
static bool has_any_child_locked(struct proc *parent)
{
    for (sz i = 0; i < PROC_MAX; i++) {
        if (i == proc_slot(parent))
            continue;
        if (proc_table[i].state != PROC_STATE_FREE &&
            proc_child_matches_parent(&proc_table[i], parent))
            return true;
    }
    return false;
}

static bool proc_child_wait_ready(struct proc *parent)
{
    u64 flags = proc_table_lock_irqsave();
    bool ready =
        has_zombie_child_locked(parent) || !has_any_child_locked(parent);
    proc_table_unlock_irqrestore(flags);
    return ready;
}

void proc_notify_parent(struct proc *child)
{
    assert(child);
    sz wake_slot = PROC_MAX; /* sentinel: no slot found */
    u64 flags = proc_table_lock_irqsave();
    for (sz i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].state != PROC_STATE_FREE &&
            proc_table[i].pid == child->parent_pid &&
            proc_table[i].generation == child->parent_generation) {
            wake_slot = i;
            break;
        }
    }
    proc_table_unlock_irqrestore(flags);

    if (wake_slot < PROC_MAX)
        wake_up(&child_wqs[wake_slot], 1);
}

i32 proc_wait_child(struct proc *parent, u16 *out_pid, i32 *out_code)
{
    assert(parent);

    /* Fast path: check for existing zombie or no children at all. */
    u64 flags = proc_table_lock_irqsave();
    bool has_zombie = has_zombie_child_locked(parent);
    bool has_any = has_any_child_locked(parent);
    proc_table_unlock_irqrestore(flags);
    if (!has_zombie && !has_any)
        return -(i32) ECHILD;

    /* Block until a child becomes zombie. */
    wait_event(child_wqs[proc_slot(parent)], proc_child_wait_ready(parent));

    /* Find and reap the first zombie child. */
    flags = proc_table_lock_irqsave();
    for (sz i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].state == PROC_STATE_ZOMBIE &&
            proc_table[i].parent_pid == parent->pid) {
            *out_pid = proc_table[i].pid;
            *out_code = proc_table[i].exit_code;
            proc_free_locked(&proc_table[i]);
            proc_table_unlock_irqrestore(flags);
            return 0;
        }
    }
    proc_table_unlock_irqrestore(flags);
    return -(i32) ECHILD;
}

struct result proc_map_user_page(struct proc *p, vaddr_t vaddr, u16 perms)
{
    assert(p);
    if (p->n_user_pages >= PROC_PAGES_MAX)
        return result_error(ENOMEM);

    struct option_byte_array ba = kvalloc_alloc(PAGE_SIZE, PAGE_SIZE);
    if (ba.is_none)
        return result_error(ENOMEM);
    struct byte_array page_ba = option_byte_array_checked(ba);
    void *page = page_ba.dat;

    memset(page, 0, PAGE_SIZE);

    struct result_paddr_t pa_res = virt_to_phys((vaddr_t) page);
    if (pa_res.is_error) {
        kvalloc_free(page_ba);
        return result_error(pa_res.code);
    }
    paddr_t pa = result_paddr_t_checked(pa_res);

    paging_map_page(vaddr, pa, perms);

    p->user_pages[p->n_user_pages].paddr = pa;
    p->user_pages[p->n_user_pages].vaddr = vaddr;
    p->n_user_pages++;

    return result_ok();
}

bool proc_unmap_user_page(struct proc *p, vaddr_t vaddr)
{
    assert(p);
    for (sz i = 0; i < p->n_user_pages; i++) {
        if (p->user_pages[i].vaddr != vaddr)
            continue;

        paging_unmap_page(vaddr);
        struct result_vaddr_t va = phys_to_virt(p->user_pages[i].paddr);
        if (!va.is_error) {
            vaddr_t kva = result_vaddr_t_checked(va);
            kvalloc_free(byte_array_new((byte *) kva, PAGE_SIZE));
        }

        p->n_user_pages--;
        p->user_pages[i] = p->user_pages[p->n_user_pages];
        p->user_pages[p->n_user_pages].paddr = 0;
        p->user_pages[p->n_user_pages].vaddr = 0;
        return true;
    }
    return false;
}

void proc_free_user_pages(struct proc *p)
{
    assert(p);
    for (sz i = 0; i < p->n_user_pages; i++) {
        paging_unmap_page(p->user_pages[i].vaddr);
        /* Convert paddr back to vaddr for kvalloc_free (identity-mapped). */
        struct result_vaddr_t va = phys_to_virt(p->user_pages[i].paddr);
        if (!va.is_error) {
            vaddr_t kva = result_vaddr_t_checked(va);
            kvalloc_free(byte_array_new((byte *) kva, PAGE_SIZE));
        }
    }
    p->n_user_pages = 0;
}

bool proc_is_missing_or_zombie(u16 pid)
{
    bool result = true;
    u64 flags = proc_table_lock_irqsave();
    for (sz i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].state != PROC_STATE_FREE &&
            proc_table[i].pid == pid) {
            result = proc_table[i].state == PROC_STATE_ZOMBIE;
            break;
        }
    }
    proc_table_unlock_irqrestore(flags);
    return result;
}

i32 proc_add_vma(struct proc *p, vaddr_t base, sz len, u16 perms)
{
    assert(p);
    if (len == 0)
        return -(i32) EINVAL;
    if ((uptr) base + (uptr) len < (uptr) base)
        return -(i32) EINVAL;
    if (p->n_vmas >= PROC_VMA_MAX)
        return -(i32) ENOMEM;
    struct vma *v = &p->vmas[p->n_vmas++];
    v->base = base;
    v->len = len;
    v->perms = perms;
    v->active = true;
    return 0;
}

bool proc_remove_vma(struct proc *p, vaddr_t base, sz len)
{
    assert(p);
    for (sz i = 0; i < p->n_vmas; i++) {
        struct vma *v = &p->vmas[i];
        if (!v->active || v->base != base || v->len != len)
            continue;

        p->n_vmas--;
        p->vmas[i] = p->vmas[p->n_vmas];
        memset(&p->vmas[p->n_vmas], 0, sizeof(p->vmas[p->n_vmas]));
        p->vma_cache_read = PROC_VMA_MAX;
        p->vma_cache_write = PROC_VMA_MAX;
        return true;
    }
    return false;
}

bool proc_vma_contains(struct proc *p, ptr addr, sz len)
{
    return proc_vma_check_access(p, addr, len, 0);
}

bool proc_vma_check_access(struct proc *p, ptr addr, sz len, u16 required_perms)
{
    if (!p)
        return false;
    if (len == 0)
        return true; /* zero-length access is always valid */

    uptr uaddr = (uptr) addr;
    uptr uend = uaddr + (uptr) len;
    if (uend < uaddr)
        return false; /* overflow */

    u8 *cache = NULL;
    if (required_perms & VMA_PERM_WRITE)
        cache = &p->vma_cache_write;
    else
        cache = &p->vma_cache_read;

    if (*cache < p->n_vmas) {
        struct vma *v = &p->vmas[*cache];
        if (v->active) {
            uptr vbase = (uptr) v->base;
            uptr vend = vbase + (uptr) v->len;
            if (uaddr >= vbase && uend <= vend) {
                if (!required_perms ||
                    (v->perms & required_perms) == required_perms)
                    return true;
                return false;
            }
        }
    }

    for (sz i = 0; i < p->n_vmas; i++) {
        struct vma *v = &p->vmas[i];
        if (!v->active)
            continue;
        uptr vbase = (uptr) v->base;
        uptr vend = vbase + (uptr) v->len;
        if (uaddr >= vbase && uend <= vend) {
            if (required_perms && (v->perms & required_perms) != required_perms)
                return false;
            *cache = (u8) i;
            return true;
        }
    }

    *cache = PROC_VMA_MAX;
    return false;
}

void proc_reparent_children(struct proc *parent)
{
    assert(parent);
    bool need_wake_init = false;
    sz init_slot = PROC_MAX;

    u64 flags = proc_table_lock_irqsave();

    /* Find PID 1 (init).  If init is missing or zombie, orphaned zombie
     * children will be auto-reaped below.
     */
    struct proc *init = NULL;
    for (sz i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].state != PROC_STATE_FREE && proc_table[i].pid == 1) {
            init = &proc_table[i];
            init_slot = i;
            break;
        }
    }
    bool init_alive = init && init->state != PROC_STATE_ZOMBIE;

    for (sz i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].state == PROC_STATE_FREE)
            continue;
        if (!proc_child_matches_parent(&proc_table[i], parent))
            continue;
        if (&proc_table[i] == parent)
            continue;

        if (init_alive) {
            proc_table[i].parent_pid = 1;
            proc_table[i].parent_generation = init->generation;
            if (proc_table[i].state == PROC_STATE_ZOMBIE)
                need_wake_init = true;
        } else {
            /* No init: auto-reap zombie children. */
            if (proc_table[i].state == PROC_STATE_ZOMBIE)
                proc_free_locked(&proc_table[i]);
            else {
                proc_table[i].parent_pid = 0; /* true orphan */
                proc_table[i].parent_generation = 0;
            }
        }
    }
    proc_table_unlock_irqrestore(flags);

    /* Deferred wake: notify init's child wait queue if zombies were
     * reparented.  Done outside proc_table_lock for lock ordering.
     */
    if (need_wake_init && init_slot < PROC_MAX)
        wake_up(&child_wqs[init_slot], 1);
}

void proc_exit(struct proc *p, i32 exit_code)
{
    if (!p)
        return;

    /* Idempotent under SMP: a concurrent SIGKILL via signal_send and
     * a normal sys_exit can both call proc_exit. The losing caller
     * sees the proc already in ZOMBIE / FREE and returns. The check
     * runs under proc_table_lock so the state read is not torn
     * against proc_free_locked's transition.
     */
    {
        u64 flags = proc_table_lock_irqsave();
        bool already_exiting = p->magic != PROC_MAGIC ||
                               p->state == PROC_STATE_ZOMBIE ||
                               p->state == PROC_STATE_FREE || p->is_exiting;
        if (already_exiting) {
            proc_table_unlock_irqrestore(flags);
            return;
        }
        /* Claim ownership of the teardown under the same lock so a second
         * caller (SIGKILL racing with sys_exit, or two threads calling
         * exit concurrently) cannot pass this guard and double-execute
         * futex_exit_robust_list / posix_timer_teardown_proc /
         * sync_handle_teardown_proc.
         */
        p->is_exiting = true;
        proc_table_unlock_irqrestore(flags);
    }

    p->exit_code = exit_code;

    /* Walk the robust futex list to unlock orphaned futexes before
     * tearing down the process.  Must happen while the task link and
     * user pages are still valid (before detach and free).
     */
    futex_exit_robust_list(p);

    /* Tear down armed POSIX timers before detaching the task link.
     * Prevents the timer expiry callback from signaling a dead process.
     */
    posix_timer_teardown_proc(p);

    /* Release sync handles owned by this process. */
    sync_handle_teardown_proc(p);

    /* Reparent children before going zombie. */
    proc_reparent_children(p);

    /* Determine parent status, detach task link, and transition to ZOMBIE
     * under a single lock hold to avoid TOCTOU and data races.
     */
    sz parent_slot = PROC_MAX;
    u64 flags = proc_table_lock_irqsave();

    /* Snapshot every attached task BEFORE detaching so the
     * TD_STATE_TERMINATING transition can run outside the proc
     * table lock. Detach order: clear tasks[] under lock, then walk
     * the snapshot to terminate each. The terminating call must run
     * without proc_table_lock because the scheduler's cleanup path
     * may also reach for that lock indirectly.
     */
    struct sched_task *terminating[PROC_THREAD_MAX];
    u8 n_terminating = 0;
    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        struct sched_task *t = p->tasks[i];
        if (!t)
            continue;
        terminating[n_terminating++] = t;
        proc_detach_task(p, t);
    }
    for (sz i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].state != PROC_STATE_FREE &&
            proc_table[i].state != PROC_STATE_ZOMBIE &&
            proc_table[i].pid == p->parent_pid &&
            proc_table[i].generation == p->parent_generation) {
            parent_slot = i;
            break;
        }
    }

    proc_set_state(p, PROC_STATE_ZOMBIE);

    bool auto_reaped = (parent_slot == PROC_MAX);
    if (auto_reaped)
        proc_free_locked(p); /* orphan: auto-reap immediately */
    proc_table_unlock_irqrestore(flags);

    /* Terminate every thread that was attached. The leader's caller
     * usually transitions itself separately (sys_exit / signal_deliver
     * SIG_DFL kill path); secondary threads need their state flipped
     * here so the scheduler stops dispatching them.
     *
     * EXITED-but-unreaped joinable threads need explicit reaping:
     * sched_destroy_dead_task previously skipped kvalloc_free
     * pending a future SYS_THREAD_JOIN, but with the proc gone no
     * join will arrive. The same atomic EXITED -> REAPED claim
     * used by the join syscall guarantees no race against a
     * concurrent sys_thread_join, eliminating any double-free
     * window.
     */
    struct sched_task *self = sched_current_task();
    for (u8 i = 0; i < n_terminating; i++) {
        struct sched_task *t = terminating[i];
        if (t == self)
            continue;
        u8 prev = (u8) TD_JOIN_EXITED;
        u8 next = (u8) TD_JOIN_REAPED;
        if (__atomic_compare_exchange_n((u8 *) &t->td_join_state, &prev, next,
                                        false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_RELAXED)) {
            sched_reap_user_thread(t);
            continue;
        }
        if (t->state != TD_STATE_TERMINATING)
            sched_set_task_state(t, TD_STATE_TERMINATING);
    }

    /* p->thread_event_wq is on the proc slot, which has been freed and may
     * already have been recycled by another CPU when auto_reaped is true.
     * Skip the wake in that case: all of this proc's threads are in the
     * terminating[] snapshot we just walked, so there's no remaining
     * in-process joiner that could be waiting on this wq.
     */
    if (!auto_reaped)
        wake_up(&p->thread_event_wq, I32_MAX);

    /* Wake parent outside the lock to respect lock ordering. */
    if (parent_slot < PROC_MAX)
        wake_up(&child_wqs[parent_slot], 1);
}

sz proc_count_children(u16 parent_pid)
{
    sz count = 0;
    u64 flags = proc_table_lock_irqsave();
    for (sz i = 0; i < PROC_MAX; i++) {
        if (proc_table[i].state != PROC_STATE_FREE &&
            proc_table[i].pid != parent_pid &&
            proc_table[i].parent_pid == parent_pid)
            count++;
    }
    proc_table_unlock_irqrestore(flags);
    return count;
}

#include __INC_TEST(proc)
