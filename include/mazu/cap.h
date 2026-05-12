/* SPDX-License-Identifier: MIT */
/* Capability-based security: public interface.
 *
 * Every process owns a fixed cap_space (CAP_SPACE_SLOTS entries). Each
 * slot is an unforgeable handle to a typed kernel object. The slot word
 * packs object_index, type, rights, type_meta, and a 32-bit generation;
 * the cap layer enforces unforgeability, single-hop delegation, lazy
 * revocation via generation bump, and an active-use pin that keeps the
 * underlying object alive across blocking syscalls.
 *
 * Userspace sees two handle shapes:
 *   - posix_fd: the small-int slot_index. This is what sys_open returns
 *     and what sys_read/sys_write/sys_close consume. The cap layer does
 *     the slot-bound permission check on every dereference.
 *   - cap_handle: a 64-bit token (cap_make_handle / cap_get_token) that
 *     carries the generation/type/rights snapshot taken at mint time.
 *     Required for cap-management syscalls that need stale-handle
 *     detection across threads or across spaces.
 *
 * Rights are a 4-bit lattice (READ, WRITE, EXEC, GRANT). Rights are
 * monotonically non-increasing on delegation: cap_transfer strips GRANT,
 * while spawn-style cap_inherit_fd preserves the source rights snapshot.
 * Plain sys_open does not mint GRANT.
 *
 * Implementation lives in kernel/proc/cap.c; the threat model, slot bit
 * layout, lock ordering, and refcount lifecycle are documented in that
 * file's header.
 */

#ifndef MAZU_CAP_H
#define MAZU_CAP_H

#include <mazu/base.h>
#include <mazu/vfs.h>

struct pipe;
struct posix_timer;
struct proc;

/* Per-process slot count. Sized from the actual object budget
 * (PROC_FD_MAX + thread/timer/IPC + reserve), not a round number.
 * No heap growth, no dynamic resize.
 */
#define CAP_SPACE_SLOTS 128

/* System-wide pool of delegate_record entries. Each cap_transfer
 * allocates one; cap_revoke_delegate consumes it. Sized to cover the
 * worst-case outstanding-delegation count across all processes.
 */
#define CAP_DELEGATE_RECORD_MAX 1024

/* Typed handle kinds. The slot word stores 4 bits, so up to 16 types
 * fit; the unused 2 are reserved for future kernel-object surfaces.
 * Adding a transferable type also requires extending cap_release_object
 * and cap_object_inc_ref dispatches in kernel/proc/cap.c.
 */
enum cap_type {
    CAP_TYPE_NONE = 0,     /* empty / dropped slot */
    CAP_TYPE_FD = 1,       /* POSIX file descriptor (VFS, pipe, console) */
    CAP_TYPE_TIMER = 2,    /* POSIX interval timer */
    CAP_TYPE_THREAD = 3,   /* pthread handle; reserved-slot range */
    CAP_TYPE_IRQ = 4,      /* IRQ control (reserved) */
    CAP_TYPE_ENDPOINT = 5, /* IPC endpoint (reserved) */
    CAP_TYPE_DELEGATE = 6, /* supervisor-side handle on an outstanding grant */
    CAP_TYPE_CAPSPACE = 7, /* meta cap on the cap_space itself (reserved) */
    CAP_TYPE_SCHED = 8,    /* scheduling control (reserved) */
    CAP_TYPE_MUTEX = 9,    /* pi_mutex pool entry */
    CAP_TYPE_CONDVAR = 10, /* condvar pool entry */
    CAP_TYPE_SEMAPHORE = 11, /* semaphore pool entry */
    CAP_TYPE_BARRIER = 12,   /* barrier pool entry */
    CAP_TYPE_RWLOCK = 13,    /* rwlock pool entry */
    CAP_TYPE_MQUEUE = 14,    /* POSIX message queue */
};

/* 4-bit rights lattice. Rights cannot be amplified after mint:
 *   - cap_transfer requires GRANT on the source and produces a
 *     destination without GRANT (single-hop attenuation).
 *   - cap_inherit_fd clones the source slot into another process for
 *     spawn-style FD inheritance, preserving the source rights snapshot.
 *   - Cap lookups verify (slot.rights & required_rights) == required_rights;
 *     a partial-rights cap is rejected for the operation that exceeds it.
 */
#define CAP_RIGHT_READ BIT(0) /* read-side ops (read, recv, get, query) */
#define CAP_RIGHT_WRITE                                                      \
    BIT(1)                     /* write-side ops (write, send, post, mutate) \
                                */
#define CAP_RIGHT_EXEC BIT(2)  /* reserved for future memory caps */
#define CAP_RIGHT_GRANT BIT(3) /* may be cap_transfer'd or inherited */

/* type_meta bit assignments for CAP_TYPE_FD. Other types reserve their
 * own bits in the same 11-bit field but do not use them today.
 */
#define CAP_FD_META_CLOEXEC BIT(0) /* close-on-exec; dup() clears it */

/* Backend tag for CAP_TYPE_FD entries. The kind selects the dispose
 * hook (vfs_close vs pipe_close vs noop for console) when the last cap
 * to the underlying object drops.
 */
enum cap_fd_kind {
    CAP_FD_KIND_CONSOLE = 0,
    CAP_FD_KIND_VFS = 1,
    CAP_FD_KIND_PIPE = 2,
};

struct cap_space {
    /* Per-slot capability word. The bit layout is documented in
     * kernel/proc/cap.c; here it is opaque -- callers go through the
     * cap_lookup_* / cap_open_* / cap_drop_* helpers.
     */
    u64 slots[CAP_SPACE_SLOTS];
    /* Per-slot grant_epoch snapshot. For slots minted by cap_transfer
     * (or by spawn-time inheritance from such a slot), this records the
     * originating delegate_record's 64-bit monotonic epoch.
     * cap_revoke_delegate's scan matches on (type, object_index,
     * delegate_epoch) so that 32-bit slot generation wrapping or two
     * unrelated grants of the same object cannot be confused. Zero for
     * slots that are not part of any outstanding delegation.
     */
    u64 delegate_epoch[CAP_SPACE_SLOTS];
};

/* Object-constructor return shape. Used by cap-system internal mint
 * paths that take a fully-resolved object pointer and assign it to a
 * slot under fd_lock.
 */
struct cap_ctor_result {
    u16 object_index;
    u8 rights;
    u16 type_meta;
};

/* Active-use pin on a kernel object. Returned by cap_lookup_fd /
 * cap_lookup_timer / cap_lookup_object after the cap is validated and
 * the underlying pool entry's refcount has been bumped. The caller MUST
 * pair every non-zeroed return with cap_put_ref so the pool entry
 * survives concurrent revocation across blocking syscalls.
 *
 * The empty / dropped state is type == CAP_TYPE_NONE; cap_put_ref
 * tests the type field (not ptr) for liveness, since lookup variants
 * for sync primitives and mqueue return ptr == NULL and fetch the
 * typed pointer via a separate _get helper.
 */
struct cap_ref {
    void *ptr;
    u16 object_index;
    u8 type;
};

/* Read-only snapshot of a cap_space slot, returned by cap_slot_read /
 * cap_lookup_slot / cap_lookup_token. The slot_index is the array
 * position; the other fields mirror the slot word.
 */
struct cap_slot_view {
    bool valid;
    u8 slot_index;
    u16 object_index;
    u8 type;
    u8 rights;
    u16 type_meta;
    u32 generation;
};

/* Per-FD pool entry. One per open file description; multiple cap_space
 * slots may reference the same entry (dup, transfer, inheritance) and
 * refcount tracks how many.
 */
struct fd_pool_entry {
    bool in_use;
    u8 kind; /* enum cap_fd_kind */
    bool pipe_read_end;
    bool is_seekable;
    u8 console_id;
    sz offset;    /* POSIX dup'd FDs share this offset */
    u32 refcount; /* cap_space slots + active-use pins */
    struct vfs_file file;
    struct pipe *pipe;
};

void cap_init(void);
void cap_space_init(struct proc *p);
void cap_space_teardown(struct proc *p);

u64 cap_make_handle(const struct cap_slot_view *slot);
i64 cap_get_token(struct proc *p, i32 slot_idx, u8 expected_type);
i64 cap_drop_token(struct proc *p, u64 token);
i64 cap_transfer(struct proc *src, u16 dst_pid, u64 token, u8 new_rights);
i64 cap_revoke_delegate(struct proc *src, u64 delegate_token);

i64 cap_close_fd(struct proc *p, i32 fd);
struct cap_ref cap_lookup_fd(struct proc *p, i32 fd, u8 required_rights);
void cap_put_ref(struct cap_ref *ref);
i32 cap_dup_fd(struct proc *p, i32 oldfd, i32 newfd_hint, bool exact_target);
i32 cap_inherit_fd(struct proc *src, struct proc *dst, i32 src_fd, i32 dst_fd);
i32 cap_open_vfs(struct proc *p,
                 struct vfs_file file,
                 u8 rights,
                 bool is_seekable,
                 i32 slot_hint,
                 bool exact_target);
i32 cap_open_pipe(struct proc *p,
                  struct pipe *pipe,
                  bool read_end,
                  u8 rights,
                  i32 slot_hint,
                  bool exact_target);
i32 cap_open_console(struct proc *p,
                     u8 console_id,
                     u8 rights,
                     i32 slot_hint,
                     bool exact_target);
i32 cap_open_handle(struct proc *p,
                    u16 object_index,
                    u8 type,
                    u8 rights,
                    i32 slot_hint,
                    bool exact_target);
i32 cap_open_timer(struct proc *p,
                   u16 object_index,
                   u8 rights,
                   i32 slot_hint,
                   bool exact_target);
bool cap_fd_is_valid(struct proc *p, i32 fd);
bool cap_fd_has_rights(struct proc *p, i32 fd, u8 rights);
bool cap_fd_is_seekable(struct proc *p, i32 fd);
bool cap_fd_is_pipe(struct proc *p, i32 fd);
bool cap_fd_pipe_read_end(struct proc *p, i32 fd);
struct cap_slot_view cap_slot_read(struct proc *p, i32 slot_idx);
i32 cap_find_free_fd(struct proc *p);
bool cap_lookup_slot(struct proc *p,
                     i32 handle,
                     u8 required_rights,
                     u8 expected_type,
                     struct cap_slot_view *out);
bool cap_lookup_token(struct proc *p,
                      u64 token,
                      u8 required_rights,
                      u8 expected_type,
                      struct cap_slot_view *out);
/* cap_lookup_object: validates a cap slot AND takes an active-use ref on the
 * underlying object. The returned cap_ref carries the type and object_index;
 * caller MUST pair every non-zero return with cap_put_ref so the object
 * survives concurrent revocation/destroy across blocking syscalls.
 * Returns a zeroed cap_ref on EBADF/EACCES/EINVAL.
 */
struct cap_ref cap_lookup_object(struct proc *p,
                                 i32 handle,
                                 u8 required_rights,
                                 u8 expected_type);
struct cap_ref cap_lookup_timer(struct proc *p, i32 handle, u8 required_rights);

#endif /* MAZU_CAP_H */
