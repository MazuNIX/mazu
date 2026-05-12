/* SPDX-License-Identifier: MIT */
/* Capability-based security for kernel objects.
 *
 * Object-bearing syscalls (FD, timer, sync primitives, message queue) gate
 * on per-process unforgeable handles instead of relying solely on the
 * coarse syscall allow-list. The least-privilege story matters for the
 * embedded AI-assistant workload: a sandboxed task can hold a cap to one
 * pipe end without thereby gaining access to every other FD the supervisor
 * owns. The cap layer composes with the existing dispatch-layer allow-list
 * (the cheap two-load bit test still runs first; cap_lookup_* is the
 * second-stage object gate).
 *
 * Threat model and properties enforced here:
 *   - Unforgeability. A 64-bit cap_handle token packs the slot index,
 *     type, rights, and a 32-bit generation snapshot. cap_validate_token
 *     rejects any token whose snapshot diverges from the live slot, so a
 *     user cannot fabricate a token for an object it never received.
 *   - Authority confinement. Caps live in a per-process cap_space (a
 *     fixed direct table). A cap minted in process A is never visible in
 *     process B unless an explicit cap_transfer or spawn-time inherit
 *     mints a fresh slot in B.
 *   - Lazy revocation. cap_drop bumps the slot generation before clearing
 *     the slot. Slot reuse is normal (a later mint into the same slot
 *     gets a fresh generation); old tokens for that slot observe EBADF
 *     on the next validate. No poisoning, no exit-time scan.
 *   - Single-hop delegation. cap_transfer requires GRANT on the source,
 *     strips GRANT from the destination, and records the originating
 *     grant_epoch so the supervisor retains a revocable handle. The
 *     delegate cannot transitively re-delegate without going through
 *     another cap_transfer that it does not hold GRANT to perform.
 *     Spawn-style cap_inherit_fd is distinct from delegation: it clones
 *     the source FD slot into a newly-created process and preserves the
 *     source rights/delegate_epoch snapshot.
 *   - Mass revocation under dup-escape. cap_revoke_delegate scans the
 *     destination cap_space for slots matching (type, object_index,
 *     delegate_epoch) and invalidates every match, neutralizing any
 *     dup() the delegate performed before revocation.
 *   - Active-use pin. cap_lookup_fd / cap_lookup_timer /
 *     cap_lookup_object bump a per-object refcount inside the proc's
 *     fd_lock and return a cap_ref; callers MUST pair every successful
 *     lookup with cap_put_ref so a concurrent close cannot recycle the
 *     underlying object slot while another thread is still operating
 *     on it.
 *   - Deadlock-free SMP. Two-process operations (cap_transfer,
 *     cap_inherit_fd, cap_revoke_delegate) acquire fd_locks in ascending
 *     pid order via the cap_lock_pair helpers, so concurrent A->B and
 *     B->A flows cannot deadlock.
 *
 * The external POSIX ABI keeps small-integer FDs: a posix_fd is literally
 * the slot_index of a CAP_TYPE_FD entry in the caller's cap_space. The
 * full 64-bit cap_handle is required only for cap-management syscalls
 * (cap_get_token / cap_drop_token / cap_transfer / cap_revoke_delegate),
 * which is the only path that needs cross-thread / cross-space stale-
 * handle detection.
 */

#include <mazu/assert.h>
#include <mazu/cap.h>
#include <mazu/error.h>
#include <mazu/print.h>
#include <mazu/proc.h>

#include "../ipc/mqueue.h"
#include "../sync/sync_handle.h"
#include "../timer/posix_timer.h"
#include "pipe.h"

#define CAP_FD_POOL_MAX (PROC_MAX * PROC_FD_MAX)
#define CAP_HANDLE_SLOT_BITS 8
#define CAP_HANDLE_SLOT_MASK ((1U << CAP_HANDLE_SLOT_BITS) - 1U)

/* Two-process cap operations (cap_{transfer,inherit_fd,revoke_delegate}) must
 * acquire per-process fd_locks in a stable order to prevent A->B vs B->A
 * deadlock under concurrent supervisor activity. The rule is: acquire the lock
 * on the lower pid first. Same-pid callers fall through to a single acquire.
 */
struct cap_lock_pair {
    struct proc *first;
    struct proc *second;
    u64 first_flags;
    u64 second_flags;
};

static inline struct cap_lock_pair cap_lock_two(struct proc *a, struct proc *b)
{
    struct cap_lock_pair lp = {0};
    if (!a || !b || a == b) {
        lp.first = a ? a : b;
        if (lp.first)
            lp.first_flags = proc_fd_lock_irqsave(lp.first);
        return lp;
    }
    if (a->pid <= b->pid) {
        lp.first = a;
        lp.second = b;
    } else {
        lp.first = b;
        lp.second = a;
    }
    lp.first_flags = proc_fd_lock_irqsave(lp.first);
    lp.second_flags = proc_fd_lock_irqsave(lp.second);
    return lp;
}

static inline void cap_unlock_two(struct cap_lock_pair *lp)
{
    if (lp->second)
        proc_fd_unlock_irqrestore(lp->second, lp->second_flags);
    if (lp->first)
        proc_fd_unlock_irqrestore(lp->first, lp->first_flags);
}

/* Slot word layout (one u64 per cap_space[i], single naturally-aligned
 * load on RV64 -- no retry loop, no seqlock needed):
 *   bit  0       : valid    (1 = live slot, 0 = revoked / never minted)
 *   bits 1..12   : object_index (12 bits, indexes the per-type pool)
 *   bits 13..16  : type     (CAP_TYPE_*; 14 used of 16 reserved)
 *   bits 17..20  : rights   (READ | WRITE | EXEC | GRANT)
 *   bits 21..31  : type_meta (per-type union; today only CLOEXEC for FD)
 *   bits 32..63  : generation (incremented on every cap_drop, lazy revoke)
 * cap_drop / cap_revoke clear bits 0..31 but preserve the generation, so
 * a stale token's snapshot-vs-live mismatch is detectable on revisit.
 */
#define CAP_SLOT_VALID_SHIFT 0
#define CAP_SLOT_OBJECT_SHIFT 1
#define CAP_SLOT_TYPE_SHIFT 13
#define CAP_SLOT_RIGHTS_SHIFT 17
#define CAP_SLOT_META_SHIFT 21
#define CAP_SLOT_GENERATION_SHIFT 32

#define CAP_SLOT_OBJECT_MASK 0xFFFU
#define CAP_SLOT_TYPE_MASK 0xFU
#define CAP_SLOT_RIGHTS_MASK 0xFU
#define CAP_SLOT_META_MASK 0x7FFU

/* cap_handle (the 64-bit token returned by cap_get_token) layout:
 *   bits  0..31  : generation snapshot (must match live slot.generation)
 *   bits 32..35  : type snapshot       (must match live slot.type)
 *   bits 36..39  : rights snapshot     (must match live slot.rights)
 *   bits 40..47  : slot_index          (8 bits; entries < CAP_SPACE_SLOTS)
 *   bits 48..63  : reserved (zero on mint, ignored on validate)
 * The snapshot is what makes handles unforgeable: a token holder cannot
 * extend its own rights, change the type, or survive a revocation just
 * by mutating the bits, because the validate path checks every snapshot
 * against the live slot under fd_lock.
 */
#define CAP_HANDLE_GEN_MASK 0xFFFFFFFFULL
#define CAP_HANDLE_TYPE_SHIFT 32
#define CAP_HANDLE_RIGHTS_SHIFT 36
#define CAP_HANDLE_SLOT_SHIFT 40

struct delegate_record {
    bool in_use;
    struct proc *dst_proc;
    u32 dst_generation;
    u16 dst_object_index;
    u8 dst_type;
    u64 grant_epoch;
    u32 refcount;
};

static struct fd_pool_entry fd_pool[CAP_FD_POOL_MAX];
static spinlock_t fd_pool_lock = SPINLOCK_INITIALIZER;
static struct delegate_record delegate_pool[CAP_DELEGATE_RECORD_MAX];
static spinlock_t delegate_lock = SPINLOCK_INITIALIZER;
static u64 next_grant_epoch = 1;

static i64 cap_drop_slot_locked(struct proc *p, struct cap_slot_view slot);

static inline u64 cap_pack_slot(bool valid,
                                u16 object_index,
                                u8 type,
                                u8 rights,
                                u16 type_meta,
                                u32 generation)
{
    return ((u64) (valid ? 1U : 0U) << CAP_SLOT_VALID_SHIFT) |
           ((u64) (object_index & CAP_SLOT_OBJECT_MASK)
            << CAP_SLOT_OBJECT_SHIFT) |
           ((u64) (type & CAP_SLOT_TYPE_MASK) << CAP_SLOT_TYPE_SHIFT) |
           ((u64) (rights & CAP_SLOT_RIGHTS_MASK) << CAP_SLOT_RIGHTS_SHIFT) |
           ((u64) (type_meta & CAP_SLOT_META_MASK) << CAP_SLOT_META_SHIFT) |
           ((u64) generation << CAP_SLOT_GENERATION_SHIFT);
}

static inline struct cap_slot_view cap_unpack_slot(u64 word, u8 slot_index)
{
    return (struct cap_slot_view) {
        .valid = (word & BIT(CAP_SLOT_VALID_SHIFT)) != 0,
        .slot_index = slot_index,
        .object_index =
            (u16) ((word >> CAP_SLOT_OBJECT_SHIFT) & CAP_SLOT_OBJECT_MASK),
        .type = (u8) ((word >> CAP_SLOT_TYPE_SHIFT) & CAP_SLOT_TYPE_MASK),
        .rights = (u8) ((word >> CAP_SLOT_RIGHTS_SHIFT) & CAP_SLOT_RIGHTS_MASK),
        .type_meta = (u16) ((word >> CAP_SLOT_META_SHIFT) & CAP_SLOT_META_MASK),
        .generation = (u32) (word >> CAP_SLOT_GENERATION_SHIFT),
    };
}

static inline u32 cap_next_generation(u32 generation)
{
    return generation + 1;
}

static inline void cap_slot_publish(struct proc *p,
                                    u8 slot_index,
                                    u16 object_index,
                                    u8 type,
                                    u8 rights,
                                    u16 type_meta,
                                    u32 generation)
{
    __atomic_store_n(
        &p->cap_space.slots[slot_index],
        cap_pack_slot(true, object_index, type, rights, type_meta, generation),
        __ATOMIC_RELEASE);
    __atomic_store_n(&p->cap_space.delegate_epoch[slot_index], 0,
                     __ATOMIC_RELEASE);
}

static inline u64 cap_slot_delegate_epoch(struct proc *p, u8 slot_index)
{
    return __atomic_load_n(&p->cap_space.delegate_epoch[slot_index],
                           __ATOMIC_ACQUIRE);
}

static inline void cap_slot_set_delegate_epoch(struct proc *p,
                                               u8 slot_index,
                                               u64 delegate_epoch)
{
    __atomic_store_n(&p->cap_space.delegate_epoch[slot_index], delegate_epoch,
                     __ATOMIC_RELEASE);
}

/* Revoke the slot. The valid bit and payload bits clear, but the
 * generation is bumped so any token still naming this slot will fail
 * validation (generation mismatch). This is the entire revocation
 * mechanism: no scan of dangling tokens, no list of grantees, no
 * cooperation from the holders. Holders observe EBADF on next use.
 */
static inline void cap_slot_invalidate(struct proc *p, u8 slot_index)
{
    u64 old =
        __atomic_load_n(&p->cap_space.slots[slot_index], __ATOMIC_ACQUIRE);
    struct cap_slot_view slot = cap_unpack_slot(old, slot_index);
    u32 generation = cap_next_generation(slot.generation);
    __atomic_store_n(&p->cap_space.slots[slot_index],
                     cap_pack_slot(false, 0, 0, 0, 0, generation),
                     __ATOMIC_RELEASE);
    __atomic_store_n(&p->cap_space.delegate_epoch[slot_index], 0,
                     __ATOMIC_RELEASE);
}

static inline struct fd_pool_entry *fd_pool_entry(u16 object_index)
{
    if (object_index >= CAP_FD_POOL_MAX)
        return NULL;
    return &fd_pool[object_index];
}

static inline struct posix_timer *timer_pool_entry(u16 object_index)
{
    return posix_timer_ptr(object_index);
}

static void cap_fd_dispose(u16 object_index)
{
    struct fd_pool_entry *entry = fd_pool_entry(object_index);
    if (!entry)
        return;

    switch (entry->kind) {
    case CAP_FD_KIND_VFS:
        vfs_close(&entry->file);
        break;
    case CAP_FD_KIND_PIPE:
        if (entry->pipe) {
            if (entry->pipe_read_end)
                pipe_close_read(entry->pipe);
            else
                pipe_close_write(entry->pipe);
        }
        break;
    case CAP_FD_KIND_CONSOLE:
    default:
        break;
    }

    memset(entry, 0, sizeof(*entry));
}

/* Drop one reference on the typed pool entry backing a capability slot.
 * Unknown types are silently ignored: a CAP_TYPE_DELEGATE slot, for example,
 * has no pool refcount of its own (the delegate_record carries the lifetime).
 */
static void cap_release_object_once(u8 type, u16 object_index)
{
    switch (type) {
    case CAP_TYPE_TIMER:
        posix_timer_put_idx(object_index);
        break;
    case CAP_TYPE_MUTEX:
        sync_mutex_put_idx((i32) object_index);
        break;
    case CAP_TYPE_CONDVAR:
        sync_condvar_put_idx((i32) object_index);
        break;
    case CAP_TYPE_SEMAPHORE:
        sync_sem_put_idx((i32) object_index);
        break;
    case CAP_TYPE_BARRIER:
        sync_barrier_put_idx((i32) object_index);
        break;
    case CAP_TYPE_RWLOCK:
        sync_rwlock_put_idx((i32) object_index);
        break;
    case CAP_TYPE_MQUEUE:
        mqueue_put_idx((i32) object_index);
        break;
    default:
        break;
    }
}

static void cap_release_object(u8 type, u16 object_index, u32 count)
{
    if (count == 0)
        return;

    /* CAP_TYPE_FD is special: its refcount lives on the pool entry itself
     * (atomic) and dispose runs only when the count actually reaches zero,
     * so iterate the atomic decrement to keep per-step zero-detection
     * (the count > 1 case is exclusive to cap_revoke_delegate's mass scan).
     */
    if (type == CAP_TYPE_FD) {
        struct fd_pool_entry *entry = fd_pool_entry(object_index);
        if (!entry)
            return;
        for (u32 i = 0; i < count; i++) {
            u32 rc = __atomic_sub_fetch(&entry->refcount, 1, __ATOMIC_ACQ_REL);
            if (rc == 0)
                cap_fd_dispose(object_index);
        }
        return;
    }

    /* Other typed pools (timer, sync, mqueue) take an internal lock per
     * decrement and have no batched put; loop the per-type hook.
     */
    for (u32 i = 0; i < count; i++)
        cap_release_object_once(type, object_index);
}

void cap_put_ref(struct cap_ref *ref)
{
    /* Test against type, not ptr: cap_lookup_object returns refs with
     * ptr=NULL for types whose typed pointer is fetched separately (sync
     * primitives, mqueue). The empty/dropped state is type == CAP_TYPE_NONE.
     */
    if (!ref || ref->type == CAP_TYPE_NONE)
        return;
    cap_release_object(ref->type, ref->object_index, 1);
    memset(ref, 0, sizeof(*ref));
}

static inline bool cap_slot_is_thread_reserved(i32 slot_index)
{
    return slot_index >= CAP_SPACE_SLOTS - PROC_THREAD_MAX &&
           slot_index < CAP_SPACE_SLOTS;
}

static i32 cap_find_free_slot_locked(struct proc *p, bool allow_thread_reserved)
{
    for (i32 i = 0; i < CAP_SPACE_SLOTS; i++) {
        if (!allow_thread_reserved && cap_slot_is_thread_reserved(i))
            continue;
        struct cap_slot_view slot = cap_unpack_slot(
            __atomic_load_n(&p->cap_space.slots[i], __ATOMIC_ACQUIRE), (u8) i);
        if (!slot.valid)
            return i;
    }
    return -1;
}

static i32 cap_reserve_slot_locked(struct proc *p,
                                   i32 slot_hint,
                                   bool exact,
                                   bool allow_thread_reserved)
{
    if (slot_hint >= 0) {
        if (slot_hint >= CAP_SPACE_SLOTS)
            return -(i32) EBADF;
        if (!allow_thread_reserved && cap_slot_is_thread_reserved(slot_hint))
            return -(i32) EBADF;
        struct cap_slot_view slot = cap_unpack_slot(
            __atomic_load_n(&p->cap_space.slots[slot_hint], __ATOMIC_ACQUIRE),
            (u8) slot_hint);
        if (!slot.valid || exact)
            return slot_hint;
    }

    i32 free_slot = cap_find_free_slot_locked(p, allow_thread_reserved);
    return free_slot >= 0 ? free_slot : -(i32) ENOSPC;
}

static i32 cap_fd_pool_alloc(enum cap_fd_kind kind)
{
    u64 flags = spin_lock_irqsave(&fd_pool_lock);
    for (i32 i = 0; i < CAP_FD_POOL_MAX; i++) {
        if (!fd_pool[i].in_use) {
            memset(&fd_pool[i], 0, sizeof(fd_pool[i]));
            fd_pool[i].in_use = true;
            fd_pool[i].kind = (u8) kind;
            __atomic_store_n(&fd_pool[i].refcount, 1, __ATOMIC_RELEASE);
            spin_unlock_irqrestore(&fd_pool_lock, flags);
            return i;
        }
    }
    spin_unlock_irqrestore(&fd_pool_lock, flags);
    return -(i32) ENFILE;
}

static void cap_fd_pool_abort_new(u16 object_index)
{
    struct fd_pool_entry *entry = fd_pool_entry(object_index);
    if (!entry)
        return;
    u32 rc = __atomic_sub_fetch(&entry->refcount, 1, __ATOMIC_ACQ_REL);
    if (rc == 0)
        cap_fd_dispose(object_index);
}

static i32 cap_mint_fd_locked(struct proc *p,
                              u16 object_index,
                              u8 rights,
                              u16 type_meta,
                              i32 slot_hint,
                              bool exact_target,
                              bool bump_ref)
{
    if (bump_ref) {
        struct fd_pool_entry *entry = fd_pool_entry(object_index);
        if (!entry || !entry->in_use)
            return -(i32) EBADF;
        __atomic_fetch_add(&entry->refcount, 1, __ATOMIC_RELAXED);
    }

    i32 slot_index = cap_reserve_slot_locked(p, slot_hint, exact_target, false);
    if (slot_index < 0) {
        if (bump_ref)
            cap_release_object(CAP_TYPE_FD, object_index, 1);
        return slot_index == -(i32) ENOSPC ? -(i32) EMFILE : slot_index;
    }

    u64 old =
        __atomic_load_n(&p->cap_space.slots[slot_index], __ATOMIC_ACQUIRE);
    struct cap_slot_view prev = cap_unpack_slot(old, (u8) slot_index);
    if (exact_target && prev.valid) {
        i64 drop_rc = cap_drop_slot_locked(p, prev);
        if (drop_rc < 0) {
            if (bump_ref)
                cap_release_object(CAP_TYPE_FD, object_index, 1);
            return (i32) drop_rc;
        }
        old =
            __atomic_load_n(&p->cap_space.slots[slot_index], __ATOMIC_ACQUIRE);
        prev = cap_unpack_slot(old, (u8) slot_index);
    }
    cap_slot_publish(p, (u8) slot_index, object_index, CAP_TYPE_FD, rights,
                     type_meta, prev.generation);
    return slot_index;
}

/* Authenticate a cap_handle token against the live cap_space slot.
 *
 * This is the unforgeability gate: a token presented by user space
 * carries a generation/type/rights snapshot taken at mint time. The
 * validate step refuses the token unless every snapshot field still
 * matches the slot. Concretely it rejects:
 *   - slot_index out of range  -> EBADF on the caller (token byzantine)
 *   - !slot.valid              -> EBADF (slot revoked or never minted)
 *   - generation mismatch      -> EBADF (slot was drop/re-minted; the
 *                                 caller is holding a stale handle)
 *   - type mismatch            -> EBADF (slot index recycled into a
 *                                 different object type)
 *   - rights mismatch          -> EBADF (the caller is presenting an
 *                                 amplified token; rights cannot be
 *                                 upgraded after mint)
 * The caller must hold the proc's fd_lock; the atomic load alone is
 * sufficient to read a consistent slot word but the lock pairs the
 * validate with whatever object-level work follows.
 */
static bool cap_validate_token_locked(struct proc *p,
                                      u64 token,
                                      struct cap_slot_view *out)
{
    u32 generation = (u32) (token & CAP_HANDLE_GEN_MASK);
    u8 type = (u8) ((token >> CAP_HANDLE_TYPE_SHIFT) & CAP_SLOT_TYPE_MASK);
    u8 rights =
        (u8) ((token >> CAP_HANDLE_RIGHTS_SHIFT) & CAP_SLOT_RIGHTS_MASK);
    u32 slot_index =
        (u32) ((token >> CAP_HANDLE_SLOT_SHIFT) & CAP_HANDLE_SLOT_MASK);

    if (slot_index >= CAP_SPACE_SLOTS)
        return false;

    struct cap_slot_view slot = cap_unpack_slot(
        __atomic_load_n(&p->cap_space.slots[slot_index], __ATOMIC_ACQUIRE),
        (u8) slot_index);
    if (!slot.valid || slot.generation != generation || slot.type != type ||
        slot.rights != rights)
        return false;
    if (out)
        *out = slot;
    return true;
}

u64 cap_make_handle(const struct cap_slot_view *slot)
{
    if (!slot || !slot->valid)
        return 0;
    return ((u64) slot->generation) |
           ((u64) slot->type << CAP_HANDLE_TYPE_SHIFT) |
           ((u64) slot->rights << CAP_HANDLE_RIGHTS_SHIFT) |
           ((u64) slot->slot_index << CAP_HANDLE_SLOT_SHIFT);
}

struct cap_slot_view cap_slot_read(struct proc *p, i32 slot_idx)
{
    if (!p || slot_idx < 0 || slot_idx >= CAP_SPACE_SLOTS)
        return (struct cap_slot_view) {0};
    u64 flags = proc_fd_lock_irqsave(p);
    struct cap_slot_view slot = cap_unpack_slot(
        __atomic_load_n(&p->cap_space.slots[slot_idx], __ATOMIC_ACQUIRE),
        (u8) slot_idx);
    proc_fd_unlock_irqrestore(p, flags);
    return slot;
}

i32 cap_find_free_fd(struct proc *p)
{
    if (!p)
        return -1;
    u64 flags = proc_fd_lock_irqsave(p);
    i32 slot = cap_find_free_slot_locked(p, false);
    proc_fd_unlock_irqrestore(p, flags);
    return slot;
}

bool cap_lookup_slot(struct proc *p,
                     i32 handle,
                     u8 required_rights,
                     u8 expected_type,
                     struct cap_slot_view *out)
{
    if (!p || handle < 0 || handle >= CAP_SPACE_SLOTS)
        return false;

    u64 flags = proc_fd_lock_irqsave(p);
    struct cap_slot_view slot = cap_unpack_slot(
        __atomic_load_n(&p->cap_space.slots[handle], __ATOMIC_ACQUIRE),
        (u8) handle);
    bool ok = slot.valid && slot.type == expected_type &&
              (slot.rights & required_rights) == required_rights;
    proc_fd_unlock_irqrestore(p, flags);
    if (!ok)
        return false;
    if (out)
        *out = slot;
    return true;
}

bool cap_lookup_token(struct proc *p,
                      u64 token,
                      u8 required_rights,
                      u8 expected_type,
                      struct cap_slot_view *out)
{
    if (!p)
        return false;

    u64 flags = proc_fd_lock_irqsave(p);
    struct cap_slot_view slot;
    bool ok = cap_validate_token_locked(p, token, &slot) &&
              slot.type == expected_type &&
              (slot.rights & required_rights) == required_rights;
    proc_fd_unlock_irqrestore(p, flags);
    if (!ok)
        return false;
    if (out)
        *out = slot;
    return true;
}

i64 cap_get_token(struct proc *p, i32 slot_idx, u8 expected_type)
{
    if (!p || slot_idx < 0 || slot_idx >= CAP_SPACE_SLOTS)
        return -(i64) EBADF;

    u64 flags = proc_fd_lock_irqsave(p);
    struct cap_slot_view slot = cap_unpack_slot(
        __atomic_load_n(&p->cap_space.slots[slot_idx], __ATOMIC_ACQUIRE),
        (u8) slot_idx);
    if (!slot.valid) {
        proc_fd_unlock_irqrestore(p, flags);
        return -(i64) EBADF;
    }
    if (slot.type != expected_type) {
        proc_fd_unlock_irqrestore(p, flags);
        return -(i64) EINVAL;
    }
    u64 handle = cap_make_handle(&slot);
    proc_fd_unlock_irqrestore(p, flags);
    return (i64) handle;
}

static i64 cap_drop_slot_locked(struct proc *p, struct cap_slot_view slot)
{
    if (!slot.valid)
        return -(i64) EBADF;

    cap_slot_invalidate(p, slot.slot_index);
    if (slot.type == CAP_TYPE_DELEGATE) {
        u16 record_index = slot.object_index;
        u64 dflags = spin_lock_irqsave(&delegate_lock);
        if (record_index < CAP_DELEGATE_RECORD_MAX &&
            delegate_pool[record_index].in_use) {
            u32 rc = __atomic_sub_fetch(&delegate_pool[record_index].refcount,
                                        1, __ATOMIC_ACQ_REL);
            if (rc == 0)
                memset(&delegate_pool[record_index], 0,
                       sizeof(delegate_pool[record_index]));
        }
        spin_unlock_irqrestore(&delegate_lock, dflags);
        return 0;
    }

    cap_release_object(slot.type, slot.object_index, 1);
    return 0;
}

i64 cap_drop_token(struct proc *p, u64 token)
{
    if (!p)
        return -(i64) EPERM;

    u64 flags = proc_fd_lock_irqsave(p);
    struct cap_slot_view slot;
    if (!cap_validate_token_locked(p, token, &slot)) {
        proc_fd_unlock_irqrestore(p, flags);
        return -(i64) EBADF;
    }
    i64 rc = cap_drop_slot_locked(p, slot);
    proc_fd_unlock_irqrestore(p, flags);
    return rc;
}

i64 cap_close_fd(struct proc *p, i32 fd)
{
    if (!p || fd < 0 || fd >= CAP_SPACE_SLOTS)
        return -(i64) EBADF;

    u64 flags = proc_fd_lock_irqsave(p);
    struct cap_slot_view slot = cap_unpack_slot(
        __atomic_load_n(&p->cap_space.slots[fd], __ATOMIC_ACQUIRE), (u8) fd);
    if (!slot.valid || slot.type != CAP_TYPE_FD) {
        proc_fd_unlock_irqrestore(p, flags);
        return -(i64) EBADF;
    }
    i64 rc = cap_drop_slot_locked(p, slot);
    proc_fd_unlock_irqrestore(p, flags);
    return rc;
}

/* Validate a cap slot of type expected_type with required_rights and bump
 * the matching pool entry's refcount under the proc's fd_lock. The pool
 * entry pointer (or NULL on failure), object_index, and is-live flag are
 * returned via the out parameters so each typed lookup helper can wrap a
 * cap_ref around the result with its own struct pointer type.
 *
 * Returns true on success. On failure (bad slot, wrong type, missing
 * rights, torn-down pool entry) returns false with the fd_lock released.
 */
static bool cap_pinned_lookup(struct proc *p,
                              i32 handle,
                              u8 required_rights,
                              u8 expected_type,
                              u16 *out_object_index,
                              void **out_entry)
{
    *out_entry = NULL;
    *out_object_index = 0;

    if (!p || handle < 0 || handle >= CAP_SPACE_SLOTS)
        return false;

    u64 flags = proc_fd_lock_irqsave(p);
    struct cap_slot_view slot = cap_unpack_slot(
        __atomic_load_n(&p->cap_space.slots[handle], __ATOMIC_ACQUIRE),
        (u8) handle);
    if (!slot.valid || slot.type != expected_type ||
        (slot.rights & required_rights) != required_rights) {
        proc_fd_unlock_irqrestore(p, flags);
        return false;
    }

    /* Each pool keeps its in_use / refcount fields at compatible offsets;
     * the typed pointer is returned as void * and reinterpreted by the
     * caller. CAP_TYPE_FD and CAP_TYPE_TIMER are the two paths that share
     * this body today.
     */
    bool ok = false;
    if (expected_type == CAP_TYPE_FD) {
        struct fd_pool_entry *entry = fd_pool_entry(slot.object_index);
        if (entry && entry->in_use) {
            __atomic_fetch_add(&entry->refcount, 1, __ATOMIC_RELAXED);
            *out_entry = entry;
            ok = true;
        }
    } else if (expected_type == CAP_TYPE_TIMER) {
        struct posix_timer *timer = timer_pool_entry(slot.object_index);
        if (timer && timer->in_use) {
            __atomic_fetch_add(&timer->refcount, 1, __ATOMIC_RELAXED);
            *out_entry = timer;
            ok = true;
        }
    }
    proc_fd_unlock_irqrestore(p, flags);

    if (ok)
        *out_object_index = slot.object_index;
    return ok;
}

struct cap_ref cap_lookup_fd(struct proc *p, i32 fd, u8 required_rights)
{
    void *entry = NULL;
    u16 object_index = 0;
    if (!cap_pinned_lookup(p, fd, required_rights, CAP_TYPE_FD, &object_index,
                           &entry))
        return (struct cap_ref) {0};
    return (struct cap_ref) {
        .ptr = entry,
        .object_index = object_index,
        .type = CAP_TYPE_FD,
    };
}

bool cap_fd_is_valid(struct proc *p, i32 fd)
{
    struct cap_slot_view slot = cap_slot_read(p, fd);
    return slot.valid && slot.type == CAP_TYPE_FD;
}

bool cap_fd_has_rights(struct proc *p, i32 fd, u8 rights)
{
    struct cap_slot_view slot = cap_slot_read(p, fd);
    return slot.valid && slot.type == CAP_TYPE_FD &&
           (slot.rights & rights) == rights;
}

bool cap_fd_is_seekable(struct proc *p, i32 fd)
{
    struct cap_ref ref = cap_lookup_fd(p, fd, 0);
    if (!ref.ptr)
        return false;
    bool seekable = ((struct fd_pool_entry *) ref.ptr)->is_seekable;
    cap_put_ref(&ref);
    return seekable;
}

bool cap_fd_is_pipe(struct proc *p, i32 fd)
{
    struct cap_ref ref = cap_lookup_fd(p, fd, 0);
    if (!ref.ptr)
        return false;
    bool is_pipe = ((struct fd_pool_entry *) ref.ptr)->kind == CAP_FD_KIND_PIPE;
    cap_put_ref(&ref);
    return is_pipe;
}

bool cap_fd_pipe_read_end(struct proc *p, i32 fd)
{
    struct cap_ref ref = cap_lookup_fd(p, fd, 0);
    if (!ref.ptr)
        return false;
    bool read_end = ((struct fd_pool_entry *) ref.ptr)->pipe_read_end;
    cap_put_ref(&ref);
    return read_end;
}

/* Type-specific active-use ref bumper. Called under the caller's fd_lock
 * after the cap_space slot has been validated. Returns true on success; false
 * if the underlying pool entry is already torn down.
 *
 * Today's transferable / lookup-pinnable types are sync primitives and mqueue.
 * FD and timer have their own dedicated lookup helpers (cap_lookup_{fd,timer})
 * that bump per-pool refcounts directly; THREAD caps are pinned by
 * proc_table_lock and don't carry a separate refcount today. Adding a new
 * transferable object type requires extending this switch AND
 * cap_release_object's dispatch.
 */
static bool cap_object_inc_ref(u8 type, u16 object_index)
{
    switch (type) {
    case CAP_TYPE_MUTEX:
        return sync_mutex_inc_idx((i32) object_index);
    case CAP_TYPE_CONDVAR:
        return sync_condvar_inc_idx((i32) object_index);
    case CAP_TYPE_SEMAPHORE:
        return sync_sem_inc_idx((i32) object_index);
    case CAP_TYPE_BARRIER:
        return sync_barrier_inc_idx((i32) object_index);
    case CAP_TYPE_RWLOCK:
        return sync_rwlock_inc_idx((i32) object_index);
    case CAP_TYPE_MQUEUE:
        return mqueue_inc_idx((i32) object_index);
    default:
        return false;
    }
}

struct cap_ref cap_lookup_object(struct proc *p,
                                 i32 handle,
                                 u8 required_rights,
                                 u8 expected_type)
{
    if (!p || handle < 0 || handle >= CAP_SPACE_SLOTS)
        return (struct cap_ref) {0};

    u64 flags = proc_fd_lock_irqsave(p);
    struct cap_slot_view slot = cap_unpack_slot(
        __atomic_load_n(&p->cap_space.slots[handle], __ATOMIC_ACQUIRE),
        (u8) handle);
    if (!slot.valid || slot.type != expected_type ||
        (slot.rights & required_rights) != required_rights) {
        proc_fd_unlock_irqrestore(p, flags);
        return (struct cap_ref) {0};
    }

    if (!cap_object_inc_ref(expected_type, slot.object_index)) {
        proc_fd_unlock_irqrestore(p, flags);
        return (struct cap_ref) {0};
    }
    proc_fd_unlock_irqrestore(p, flags);

    return (struct cap_ref) {
        .ptr = NULL,
        .object_index = slot.object_index,
        .type = expected_type,
    };
}

struct cap_ref cap_lookup_timer(struct proc *p, i32 handle, u8 required_rights)
{
    void *entry = NULL;
    u16 object_index = 0;
    if (!cap_pinned_lookup(p, handle, required_rights, CAP_TYPE_TIMER,
                           &object_index, &entry))
        return (struct cap_ref) {0};
    return (struct cap_ref) {
        .ptr = entry,
        .object_index = object_index,
        .type = CAP_TYPE_TIMER,
    };
}

i32 cap_open_vfs(struct proc *p,
                 struct vfs_file file,
                 u8 rights,
                 bool is_seekable,
                 i32 slot_hint,
                 bool exact_target)
{
    i32 object_index = cap_fd_pool_alloc(CAP_FD_KIND_VFS);
    if (object_index < 0) {
        vfs_close(&file);
        return object_index;
    }

    struct fd_pool_entry *entry = fd_pool_entry((u16) object_index);
    entry->file = file;
    entry->is_seekable = is_seekable;

    u64 flags = proc_fd_lock_irqsave(p);
    i32 fd = cap_mint_fd_locked(p, (u16) object_index, rights, 0, slot_hint,
                                exact_target, false);
    proc_fd_unlock_irqrestore(p, flags);
    if (fd < 0) {
        cap_fd_pool_abort_new((u16) object_index);
        return fd;
    }
    return fd;
}

i32 cap_open_pipe(struct proc *p,
                  struct pipe *pipe,
                  bool read_end,
                  u8 rights,
                  i32 slot_hint,
                  bool exact_target)
{
    i32 object_index = cap_fd_pool_alloc(CAP_FD_KIND_PIPE);
    if (object_index < 0) {
        if (read_end)
            pipe_close_read(pipe);
        else
            pipe_close_write(pipe);
        return object_index;
    }

    struct fd_pool_entry *entry = fd_pool_entry((u16) object_index);
    entry->pipe = pipe;
    entry->pipe_read_end = read_end;
    entry->is_seekable = false;

    u64 flags = proc_fd_lock_irqsave(p);
    i32 fd = cap_mint_fd_locked(p, (u16) object_index, rights, 0, slot_hint,
                                exact_target, false);
    proc_fd_unlock_irqrestore(p, flags);
    if (fd < 0) {
        cap_fd_pool_abort_new((u16) object_index);
        return fd;
    }
    return fd;
}

i32 cap_open_console(struct proc *p,
                     u8 console_id,
                     u8 rights,
                     i32 slot_hint,
                     bool exact_target)
{
    i32 object_index = cap_fd_pool_alloc(CAP_FD_KIND_CONSOLE);
    if (object_index < 0)
        return object_index;

    struct fd_pool_entry *entry = fd_pool_entry((u16) object_index);
    entry->console_id = console_id;
    entry->is_seekable = false;

    u64 flags = proc_fd_lock_irqsave(p);
    i32 fd = cap_mint_fd_locked(p, (u16) object_index, rights, 0, slot_hint,
                                exact_target, false);
    proc_fd_unlock_irqrestore(p, flags);
    if (fd < 0) {
        cap_fd_pool_abort_new((u16) object_index);
        return fd;
    }
    return fd;
}

i32 cap_open_handle(struct proc *p,
                    u16 object_index,
                    u8 type,
                    u8 rights,
                    i32 slot_hint,
                    bool exact_target)
{
    if (!p)
        return -(i32) EINVAL;

    u64 flags = proc_fd_lock_irqsave(p);
    i32 handle = cap_reserve_slot_locked(p, slot_hint, exact_target,
                                         type == CAP_TYPE_THREAD);
    if (handle >= 0) {
        u64 old =
            __atomic_load_n(&p->cap_space.slots[handle], __ATOMIC_ACQUIRE);
        struct cap_slot_view prev = cap_unpack_slot(old, (u8) handle);
        if (exact_target && prev.valid)
            (void) cap_drop_slot_locked(p, prev);
        old = __atomic_load_n(&p->cap_space.slots[handle], __ATOMIC_ACQUIRE);
        prev = cap_unpack_slot(old, (u8) handle);
        cap_slot_publish(p, (u8) handle, object_index, type, rights, 0,
                         prev.generation);
    }
    proc_fd_unlock_irqrestore(p, flags);
    return handle < 0 ? (handle == -(i32) ENOSPC ? -(i32) EMFILE : handle)
                      : handle;
}

i32 cap_open_timer(struct proc *p,
                   u16 object_index,
                   u8 rights,
                   i32 slot_hint,
                   bool exact_target)
{
    if (!p || !timer_pool_entry(object_index))
        return -(i32) EINVAL;
    return cap_open_handle(p, object_index, CAP_TYPE_TIMER, rights, slot_hint,
                           exact_target);
}

i32 cap_dup_fd(struct proc *p, i32 oldfd, i32 newfd_hint, bool exact_target)
{
    if (!p || oldfd < 0 || oldfd >= PROC_FD_MAX)
        return -(i32) EBADF;
    if (exact_target && (newfd_hint < 0 || newfd_hint >= PROC_FD_MAX))
        return -(i32) EBADF;

    u64 flags = proc_fd_lock_irqsave(p);
    struct cap_slot_view slot = cap_unpack_slot(
        __atomic_load_n(&p->cap_space.slots[oldfd], __ATOMIC_ACQUIRE),
        (u8) oldfd);
    if (!slot.valid || slot.type != CAP_TYPE_FD) {
        proc_fd_unlock_irqrestore(p, flags);
        return -(i32) EBADF;
    }

    if (exact_target && newfd_hint == oldfd) {
        proc_fd_unlock_irqrestore(p, flags);
        return oldfd;
    }
    i32 fd = cap_mint_fd_locked(p, slot.object_index, slot.rights,
                                slot.type_meta & ~CAP_FD_META_CLOEXEC,
                                newfd_hint, exact_target, true);
    if (fd >= 0)
        cap_slot_set_delegate_epoch(p, (u8) fd,
                                    cap_slot_delegate_epoch(p, (u8) oldfd));
    proc_fd_unlock_irqrestore(p, flags);
    return fd;
}

i32 cap_inherit_fd(struct proc *src, struct proc *dst, i32 src_fd, i32 dst_fd)
{
    if (!src || !dst || src_fd < 0 || src_fd >= PROC_FD_MAX)
        return -(i32) EBADF;
    if (dst_fd < 0 || dst_fd >= PROC_FD_MAX)
        return -(i32) EBADF;
    if (src == dst)
        return cap_dup_fd(src, src_fd, dst_fd, true);

    struct cap_lock_pair lp = cap_lock_two(src, dst);
    struct cap_slot_view slot = cap_unpack_slot(
        __atomic_load_n(&src->cap_space.slots[src_fd], __ATOMIC_ACQUIRE),
        (u8) src_fd);
    if (!slot.valid || slot.type != CAP_TYPE_FD) {
        cap_unlock_two(&lp);
        return -(i32) EBADF;
    }
    i32 fd = cap_mint_fd_locked(dst, slot.object_index, slot.rights,
                                slot.type_meta, dst_fd, true, true);
    if (fd >= 0)
        cap_slot_set_delegate_epoch(dst, (u8) fd,
                                    cap_slot_delegate_epoch(src, (u8) src_fd));
    cap_unlock_two(&lp);
    return fd;
}

static i32 delegate_record_alloc(struct proc *dst,
                                 u16 dst_object_index,
                                 u8 dst_type)
{
    u64 flags = spin_lock_irqsave(&delegate_lock);
    for (i32 i = 0; i < CAP_DELEGATE_RECORD_MAX; i++) {
        if (!delegate_pool[i].in_use) {
            delegate_pool[i].in_use = true;
            delegate_pool[i].dst_proc = dst;
            delegate_pool[i].dst_generation = dst ? dst->generation : 0;
            delegate_pool[i].dst_object_index = dst_object_index;
            delegate_pool[i].dst_type = dst_type;
            delegate_pool[i].grant_epoch =
                __atomic_fetch_add(&next_grant_epoch, 1, __ATOMIC_RELAXED);
            __atomic_store_n(&delegate_pool[i].refcount, 1, __ATOMIC_RELEASE);
            spin_unlock_irqrestore(&delegate_lock, flags);
            return i;
        }
    }
    spin_unlock_irqrestore(&delegate_lock, flags);
    return -(i32) ENOSPC;
}

static void delegate_record_put(u16 record_index)
{
    u64 flags = spin_lock_irqsave(&delegate_lock);
    if (record_index < CAP_DELEGATE_RECORD_MAX &&
        delegate_pool[record_index].in_use) {
        u32 rc = __atomic_sub_fetch(&delegate_pool[record_index].refcount, 1,
                                    __ATOMIC_ACQ_REL);
        if (rc == 0)
            memset(&delegate_pool[record_index], 0, sizeof(delegate_pool[0]));
    }
    spin_unlock_irqrestore(&delegate_lock, flags);
}

i64 cap_transfer(struct proc *src, u16 dst_pid, u64 token, u8 new_rights)
{
    if (!src)
        return -(i64) EPERM;

    if ((new_rights & CAP_RIGHT_GRANT) != 0)
        return -(i64) EINVAL;

    struct proc *dst = proc_find(dst_pid);
    if (!dst)
        return -(i64) ESRCH;
    if (dst == src)
        return -(i64) EINVAL;

    struct cap_lock_pair lp = cap_lock_two(src, dst);
    struct cap_slot_view src_slot;
    if (!cap_validate_token_locked(src, token, &src_slot)) {
        cap_unlock_two(&lp);
        return -(i64) EBADF;
    }
    if (src_slot.type != CAP_TYPE_FD) {
        cap_unlock_two(&lp);
        return -(i64) EINVAL;
    }
    if ((src_slot.rights & CAP_RIGHT_GRANT) == 0) {
        cap_unlock_two(&lp);
        return -(i64) EACCES;
    }
    if ((new_rights & src_slot.rights) != new_rights) {
        cap_unlock_two(&lp);
        return -(i64) EINVAL;
    }

    i32 child_fd = cap_mint_fd_locked(dst, src_slot.object_index,
                                      new_rights & ~CAP_RIGHT_GRANT,
                                      src_slot.type_meta, -1, false, true);
    if (child_fd < 0) {
        cap_unlock_two(&lp);
        return child_fd == -(i32) EMFILE ? -(i64) ENOSPC : child_fd;
    }

    i32 record_index =
        delegate_record_alloc(dst, src_slot.object_index, src_slot.type);
    if (record_index < 0) {
        struct cap_slot_view child_slot = cap_unpack_slot(
            __atomic_load_n(&dst->cap_space.slots[child_fd], __ATOMIC_ACQUIRE),
            (u8) child_fd);
        cap_drop_slot_locked(dst, child_slot);
        cap_unlock_two(&lp);
        return -(i64) ENOSPC;
    }

    i32 delegate_slot = cap_reserve_slot_locked(src, -1, false, false);
    if (delegate_slot < 0) {
        struct cap_slot_view child_slot = cap_unpack_slot(
            __atomic_load_n(&dst->cap_space.slots[child_fd], __ATOMIC_ACQUIRE),
            (u8) child_fd);
        cap_drop_slot_locked(dst, child_slot);
        delegate_record_put((u16) record_index);
        cap_unlock_two(&lp);
        return -(i64) ENOSPC;
    }

    u64 old =
        __atomic_load_n(&src->cap_space.slots[delegate_slot], __ATOMIC_ACQUIRE);
    struct cap_slot_view prev = cap_unpack_slot(old, (u8) delegate_slot);
    cap_slot_set_delegate_epoch(dst, (u8) child_fd,
                                delegate_pool[record_index].grant_epoch);
    cap_slot_publish(src, (u8) delegate_slot, (u16) record_index,
                     CAP_TYPE_DELEGATE, CAP_RIGHT_READ, 0, prev.generation);
    struct cap_slot_view handle_slot = cap_unpack_slot(
        __atomic_load_n(&src->cap_space.slots[delegate_slot], __ATOMIC_ACQUIRE),
        (u8) delegate_slot);

    cap_unlock_two(&lp);
    return (i64) cap_make_handle(&handle_slot);
}

static i64 cap_revoke_delegate_impl(struct proc *src,
                                    u64 delegate_token,
                                    bool proc_table_locked)
{
    if (!src)
        return -(i64) EPERM;

    /* Phase 1: under src lock, validate the DELEGATE handle, snapshot
     * the underlying delegate_record, and bump the record refcount so
     * it survives the lock dance below.
     */
    u64 sflags = proc_fd_lock_irqsave(src);
    struct cap_slot_view delegate_slot;
    if (!cap_validate_token_locked(src, delegate_token, &delegate_slot) ||
        delegate_slot.type != CAP_TYPE_DELEGATE) {
        proc_fd_unlock_irqrestore(src, sflags);
        return -(i64) EBADF;
    }

    u16 record_index = delegate_slot.object_index;
    if (record_index >= CAP_DELEGATE_RECORD_MAX ||
        !delegate_pool[record_index].in_use) {
        proc_fd_unlock_irqrestore(src, sflags);
        return -(i64) EBADF;
    }

    __atomic_fetch_add(&delegate_pool[record_index].refcount, 1,
                       __ATOMIC_RELAXED);
    struct proc *dst = delegate_pool[record_index].dst_proc;
    u32 dst_generation = delegate_pool[record_index].dst_generation;
    u16 object_index = delegate_pool[record_index].dst_object_index;
    u8 type = delegate_pool[record_index].dst_type;
    u64 grant_epoch = delegate_pool[record_index].grant_epoch;

    if (!dst || dst->generation != dst_generation) {
        cap_drop_slot_locked(src, delegate_slot);
        proc_fd_unlock_irqrestore(src, sflags);
        delegate_record_put(record_index);
        return 0;
    }

    /* Phase 2: release src lock and re-acquire BOTH locks in ascending
     * pid order so cap_revoke_delegate is deadlock-free against a
     * concurrent cap_transfer / cap_revoke_delegate / cap_inherit_fd in
     * the opposite direction.
     */
    proc_fd_unlock_irqrestore(src, sflags);

    struct proc *descendants[PROC_MAX];
    u32 descendant_generations[PROC_MAX];
    u32 revoked = 0;

    for (;;) {
        sz ndesc = proc_table_locked ? proc_collect_descendants_locked(
                                           dst, dst_generation, descendants,
                                           descendant_generations, PROC_MAX)
                                     : proc_collect_descendants(
                                           dst, dst_generation, descendants,
                                           descendant_generations, PROC_MAX);
        u32 pass_revoked = 0;

        for (sz n = 0; n < ndesc; n++) {
            struct proc *target = descendants[n];
            if (!target || target->generation != descendant_generations[n])
                continue;

            u64 dflags = proc_fd_lock_irqsave(target);
            if (target->state == PROC_STATE_FREE ||
                target->generation != descendant_generations[n]) {
                proc_fd_unlock_irqrestore(target, dflags);
                continue;
            }
            for (i32 i = 0; i < CAP_SPACE_SLOTS; i++) {
                struct cap_slot_view slot =
                    cap_unpack_slot(__atomic_load_n(&target->cap_space.slots[i],
                                                    __ATOMIC_ACQUIRE),
                                    (u8) i);
                if (!slot.valid || slot.type != type ||
                    slot.object_index != object_index ||
                    cap_slot_delegate_epoch(target, (u8) i) != grant_epoch)
                    continue;
                cap_slot_invalidate(target, (u8) i);
                pass_revoked++;
            }
            proc_fd_unlock_irqrestore(target, dflags);
        }

        revoked += pass_revoked;
        if (pass_revoked == 0)
            break;
    }

    sflags = proc_fd_lock_irqsave(src);
    if (cap_validate_token_locked(src, delegate_token, &delegate_slot) &&
        delegate_slot.type == CAP_TYPE_DELEGATE)
        cap_drop_slot_locked(src, delegate_slot);
    proc_fd_unlock_irqrestore(src, sflags);

    if (revoked > 0)
        cap_release_object(type, object_index, revoked);
    delegate_record_put(record_index);
    return 0;
}

i64 cap_revoke_delegate(struct proc *src, u64 delegate_token)
{
    return cap_revoke_delegate_impl(src, delegate_token, false);
}

void cap_init(void)
{
    memset(fd_pool, 0, sizeof(fd_pool));
    memset(delegate_pool, 0, sizeof(delegate_pool));
    fd_pool_lock = (spinlock_t) SPINLOCK_INITIALIZER;
    delegate_lock = (spinlock_t) SPINLOCK_INITIALIZER;
    __atomic_store_n(&next_grant_epoch, 1, __ATOMIC_RELAXED);
}

void cap_space_init(struct proc *p)
{
    assert(p);
    memset(&p->cap_space, 0, sizeof(p->cap_space));

    /* Fixed stdio slots preserve the existing ABI expectations. */
    (void) cap_open_console(p, PROC_FD_STDIN, CAP_RIGHT_READ | CAP_RIGHT_GRANT,
                            PROC_FD_STDIN, true);
    (void) cap_open_console(p, PROC_FD_STDOUT,
                            CAP_RIGHT_WRITE | CAP_RIGHT_GRANT, PROC_FD_STDOUT,
                            true);
    (void) cap_open_console(p, PROC_FD_STDERR,
                            CAP_RIGHT_WRITE | CAP_RIGHT_GRANT, PROC_FD_STDERR,
                            true);
}

void cap_space_teardown(struct proc *p)
{
    assert(p);

    /* Revoke delegates first so children lose access before we tear down
     * our own handles.
     */
    for (i32 i = 0; i < CAP_SPACE_SLOTS; i++) {
        struct cap_slot_view slot = cap_slot_read(p, i);
        if (!slot.valid || slot.type != CAP_TYPE_DELEGATE)
            continue;
        (void) cap_revoke_delegate_impl(p, cap_make_handle(&slot), true);
    }

    u64 flags = proc_fd_lock_irqsave(p);
    for (i32 i = 0; i < CAP_SPACE_SLOTS; i++) {
        struct cap_slot_view slot = cap_unpack_slot(
            __atomic_load_n(&p->cap_space.slots[i], __ATOMIC_ACQUIRE), (u8) i);
        if (!slot.valid)
            continue;
        (void) cap_drop_slot_locked(p, slot);
    }
    proc_fd_unlock_irqrestore(p, flags);
}

#include __INC_TEST(cap)
