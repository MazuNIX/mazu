/* SPDX-License-Identifier: MIT */
/* Handle table for PSE51 synchronization objects.
 *
 * Each slot tracks the owning process (pointer + generation) for
 * cross-process isolation.  get() returns NULL if the caller is not
 * the owner, preventing handle-guessing attacks.
 */

#include "sync_handle.h"
#include <mazu/init.h>
#include <mazu/proc.h>
#include <mazu/spinlock.h>

static struct sync_mutex_slot mutex_pool[SYNC_MAX_MUTEXES];
static struct sync_condvar_slot condvar_pool[SYNC_MAX_CONDVARS];
static struct sync_sem_slot sem_pool[SYNC_MAX_SEMAPHORES];
static struct sync_barrier_slot barrier_pool[SYNC_MAX_BARRIERS];
static struct sync_rwlock_slot rwlock_pool[SYNC_MAX_RWLOCKS];
static spinlock_t sync_lock = SPINLOCK_INITIALIZER;

/* Ownership check: slot must be in_use and caller must match owner+generation.
 * NULL owner (kernel tasks) matches NULL caller.
 */
static inline bool sync_owner_ok(struct proc *owner,
                                 u32 gen,
                                 struct proc *caller)
{
    if (!owner && !caller)
        return true; /* kernel-internal handle */
    return owner == caller && caller && gen == caller->generation;
}

/* Generate the five near-identical pool helper functions
 * (_inc_idx, _put_idx, _free_idx, _get, _free) for one sync type.
 *
 * - prefix:       function-name prefix (e.g. sync_mutex)
 * - prim_type:    primitive struct exposed via _get (e.g. struct pi_mutex)
 * - prim_field:   field name of the primitive inside the slot (e.g. mtx)
 * - pool_var:     pool array (e.g. mutex_pool)
 * - pool_size:    pool capacity macro (e.g. SYNC_MAX_MUTEXES)
 *
 * The slot struct type is inferred via typeof((pool_var)[0]); this avoids
 * a redundant type parameter and the clang-tidy bugprone-macro-parentheses
 * false positive that triggers on bare type names inside macros.
 *
 * _alloc and _init differ in arity (sem takes initial_count, barrier takes
 * count, the others take none), so each type still defines _alloc inline.
 */
#define SYNC_POOL_DEFINE(prefix, prim_type, prim_field, pool_var, pool_size) \
    prim_type *prefix##_get(i32 handle)                                      \
    {                                                                        \
        if (handle < 0 || handle >= (pool_size))                             \
            return NULL;                                                     \
        typeof(&(pool_var)[0]) s = &(pool_var)[handle];                      \
        if (!s->in_use)                                                      \
            return NULL;                                                     \
        return &s->prim_field;                                               \
    }                                                                        \
                                                                             \
    bool prefix##_inc_idx(i32 handle)                                        \
    {                                                                        \
        if (handle < 0 || handle >= (pool_size))                             \
            return false;                                                    \
        u64 flags = spin_lock_irqsave(&sync_lock);                           \
        typeof(&(pool_var)[0]) s = &(pool_var)[handle];                      \
        if (!s->in_use) {                                                    \
            spin_unlock_irqrestore(&sync_lock, flags);                       \
            return false;                                                    \
        }                                                                    \
        s->refcount++;                                                       \
        spin_unlock_irqrestore(&sync_lock, flags);                           \
        return true;                                                         \
    }                                                                        \
                                                                             \
    void prefix##_free(i32 handle, struct proc *caller)                      \
    {                                                                        \
        if (handle < 0 || handle >= (pool_size))                             \
            return;                                                          \
        u64 flags = spin_lock_irqsave(&sync_lock);                           \
        typeof(&(pool_var)[0]) s = &(pool_var)[handle];                      \
        if (s->in_use && sync_owner_ok(s->owner, s->owner_gen, caller)) {    \
            s->in_use = false;                                               \
            s->owner = NULL;                                                 \
        }                                                                    \
        spin_unlock_irqrestore(&sync_lock, flags);                           \
    }                                                                        \
                                                                             \
    void prefix##_free_idx(i32 handle)                                       \
    {                                                                        \
        if (handle < 0 || handle >= (pool_size))                             \
            return;                                                          \
        u64 flags = spin_lock_irqsave(&sync_lock);                           \
        (pool_var)[handle].in_use = false;                                   \
        (pool_var)[handle].owner = NULL;                                     \
        (pool_var)[handle].refcount = 0;                                     \
        spin_unlock_irqrestore(&sync_lock, flags);                           \
    }                                                                        \
                                                                             \
    void prefix##_put_idx(i32 handle)                                        \
    {                                                                        \
        if (handle < 0 || handle >= (pool_size))                             \
            return;                                                          \
        u64 flags = spin_lock_irqsave(&sync_lock);                           \
        typeof(&(pool_var)[0]) s = &(pool_var)[handle];                      \
        if (!s->in_use) {                                                    \
            spin_unlock_irqrestore(&sync_lock, flags);                       \
            return;                                                          \
        }                                                                    \
        if (s->refcount <= 1) {                                              \
            s->refcount = 0;                                                 \
            s->in_use = false;                                               \
            s->owner = NULL;                                                 \
        } else {                                                             \
            s->refcount--;                                                   \
        }                                                                    \
        spin_unlock_irqrestore(&sync_lock, flags);                           \
    }

/* Walk pool_var looking for the first slot with !in_use; stamp ownership
 * and refcount=1 into it, leave *slot_ptr pointing at it, and break with
 * idx set to its index. If no slot is free, idx remains -1.
 *
 * The caller wires up the primitive after the reserve (the primitive's
 * init() signature differs per type, so it cannot be folded in here).
 */
#define SYNC_POOL_RESERVE(pool_var, pool_size, owner_arg, idx_out, slot_out) \
    do {                                                                     \
        (idx_out) = -1;                                                      \
        for (i32 _i = 0; _i < (pool_size); _i++) {                           \
            if (!(pool_var)[_i].in_use) {                                    \
                (pool_var)[_i].in_use = true;                                \
                (pool_var)[_i].owner = (owner_arg);                          \
                (pool_var)[_i].owner_gen =                                   \
                    (owner_arg) ? (owner_arg)->generation : 0;               \
                (pool_var)[_i].refcount = 1;                                 \
                (slot_out) = &(pool_var)[_i];                                \
                (idx_out) = _i;                                              \
                break;                                                       \
            }                                                                \
        }                                                                    \
    } while (0)

void sync_handle_init(void)
{
    for (i32 i = 0; i < SYNC_MAX_MUTEXES; i++)
        mutex_pool[i].in_use = false;
    for (i32 i = 0; i < SYNC_MAX_CONDVARS; i++)
        condvar_pool[i].in_use = false;
    for (i32 i = 0; i < SYNC_MAX_SEMAPHORES; i++)
        sem_pool[i].in_use = false;
    for (i32 i = 0; i < SYNC_MAX_BARRIERS; i++)
        barrier_pool[i].in_use = false;
    for (i32 i = 0; i < SYNC_MAX_RWLOCKS; i++)
        rwlock_pool[i].in_use = false;
}

/* sync_*_get returns the kernel-internal primitive pointer for a live
 * pool slot. It assumes the capability layer has already authorized the
 * caller (and pinned an active-use refcount via sync_*_inc_idx); the
 * historical owner check is therefore retired: the cap is the
 * authority, not the pool's owner pointer.
 */
SYNC_POOL_DEFINE(sync_mutex, struct pi_mutex, mtx, mutex_pool, SYNC_MAX_MUTEXES)
SYNC_POOL_DEFINE(sync_condvar,
                 struct condvar,
                 cv,
                 condvar_pool,
                 SYNC_MAX_CONDVARS)
SYNC_POOL_DEFINE(sync_sem, struct semaphore, sem, sem_pool, SYNC_MAX_SEMAPHORES)
SYNC_POOL_DEFINE(sync_barrier,
                 struct barrier,
                 bar,
                 barrier_pool,
                 SYNC_MAX_BARRIERS)
SYNC_POOL_DEFINE(sync_rwlock, struct rwlock, rw, rwlock_pool, SYNC_MAX_RWLOCKS)

i32 sync_mutex_alloc(struct proc *owner)
{
    struct sync_mutex_slot *s = NULL;
    i32 idx;
    u64 flags = spin_lock_irqsave(&sync_lock);
    SYNC_POOL_RESERVE(mutex_pool, SYNC_MAX_MUTEXES, owner, idx, s);
    if (idx >= 0)
        pi_mutex_init(&s->mtx);
    spin_unlock_irqrestore(&sync_lock, flags);
    return idx < 0 ? -(i32) EAGAIN : idx;
}

i32 sync_condvar_alloc(struct proc *owner)
{
    struct sync_condvar_slot *s = NULL;
    i32 idx;
    u64 flags = spin_lock_irqsave(&sync_lock);
    SYNC_POOL_RESERVE(condvar_pool, SYNC_MAX_CONDVARS, owner, idx, s);
    if (idx >= 0)
        condvar_init(&s->cv);
    spin_unlock_irqrestore(&sync_lock, flags);
    return idx < 0 ? -(i32) EAGAIN : idx;
}

i32 sync_sem_alloc(struct proc *owner, i32 initial_count)
{
    if (initial_count < 0)
        return -(i32) EINVAL;
    struct sync_sem_slot *s = NULL;
    i32 idx;
    u64 flags = spin_lock_irqsave(&sync_lock);
    SYNC_POOL_RESERVE(sem_pool, SYNC_MAX_SEMAPHORES, owner, idx, s);
    if (idx >= 0)
        sem_init(&s->sem, initial_count);
    spin_unlock_irqrestore(&sync_lock, flags);
    return idx < 0 ? -(i32) EAGAIN : idx;
}

i32 sync_barrier_alloc(struct proc *owner, u32 count)
{
    if (count == 0)
        return -(i32) EINVAL;
    struct sync_barrier_slot *s = NULL;
    i32 idx;
    u64 flags = spin_lock_irqsave(&sync_lock);
    SYNC_POOL_RESERVE(barrier_pool, SYNC_MAX_BARRIERS, owner, idx, s);
    if (idx >= 0)
        barrier_init(&s->bar, count);
    spin_unlock_irqrestore(&sync_lock, flags);
    return idx < 0 ? -(i32) EAGAIN : idx;
}

i32 sync_rwlock_alloc(struct proc *owner)
{
    struct sync_rwlock_slot *s = NULL;
    i32 idx;
    u64 flags = spin_lock_irqsave(&sync_lock);
    SYNC_POOL_RESERVE(rwlock_pool, SYNC_MAX_RWLOCKS, owner, idx, s);
    if (idx >= 0)
        rwlock_init(&s->rw);
    spin_unlock_irqrestore(&sync_lock, flags);
    return idx < 0 ? -(i32) EAGAIN : idx;
}

/* Per-type tear-down walker. Called once per pool from
 * sync_handle_teardown_proc under sync_lock. Releases every slot owned by p.
 */
#define SYNC_TEARDOWN_POOL(pool_var, pool_size, proc_ptr)              \
    do {                                                               \
        for (i32 _i = 0; _i < (pool_size); _i++) {                     \
            typeof((pool_var)[0]) *_s = &(pool_var)[_i];               \
            if (_s->in_use &&                                          \
                sync_owner_ok(_s->owner, _s->owner_gen, (proc_ptr))) { \
                _s->in_use = false;                                    \
                _s->owner = NULL;                                      \
            }                                                          \
        }                                                              \
    } while (0)

void sync_handle_teardown_proc(struct proc *p)
{
    u64 flags = spin_lock_irqsave(&sync_lock);
    SYNC_TEARDOWN_POOL(mutex_pool, SYNC_MAX_MUTEXES, p);
    SYNC_TEARDOWN_POOL(condvar_pool, SYNC_MAX_CONDVARS, p);
    SYNC_TEARDOWN_POOL(sem_pool, SYNC_MAX_SEMAPHORES, p);
    SYNC_TEARDOWN_POOL(barrier_pool, SYNC_MAX_BARRIERS, p);
    SYNC_TEARDOWN_POOL(rwlock_pool, SYNC_MAX_RWLOCKS, p);
    spin_unlock_irqrestore(&sync_lock, flags);
}

static void sync_handle_boot_init(u32 flag __unused)
{
    sync_handle_init();
}
DEFINE_INIT_HOOK(sync_handle_boot_init, INIT_LEVEL_SUBSYS, INIT_FLAG_PRIMARY);
