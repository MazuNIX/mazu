/* SPDX-License-Identifier: MIT */
/* Syscall dispatch for user-space processes.
 *
 * Called from trap_dispatch() when scause == ECALL_U.  The trapframe's
 * a7 selects the syscall number; a0-a5 carry arguments.  Return value
 * is placed in a0 by the caller.
 *
 * Security invariant: all user pointers must pass through copy_from_user /
 * copy_to_user.  Direct dereference of user pointers is forbidden.
 * Invalid syscall numbers return -ENOSYS; this is not a security hole
 * because user-space can already invoke any ecall.
 */

#include <mazu/assert.h>
#include <mazu/cap.h>
#include <mazu/eventlog.h>
#include <mazu/ipi.h>
#include <mazu/klog.h>
#include <mazu/kvalloc.h>
#include <mazu/pcpu.h>
#include <mazu/posix_time.h>
#include <mazu/print.h>
#include <mazu/proc.h>
#include <mazu/sched.h>
#include <mazu/spawn.h>
#include <mazu/string.h>
#include <mazu/syscall.h>
#include <mazu/sysconf.h>
#include <mazu/time.h>
#include <mazu/uaccess.h>
#include <mazu/vfs.h>

#include "../ipc/mqueue.h"
#include "../sched/waitqueue.h"
#include "../sync/futex.h"
#include "../sync/mutex.h"
#include "../sync/sync_handle.h"
#include "../timer/posix_timer.h"
#include "elf64.h"
#include "pipe.h"
#include "signal.h"

/* The per-process allow-list (struct proc::syscall_allow[2]) is two u64 words
 * indexed by (nr / 64). Adding a 65th syscall without widening the array
 * silently writes past the end during dispatch.
 */
static_assert(SYS_NR <= 128, "syscall_allow[2] only covers nrs 0..127");

static i64 cancel_thread_now(struct trap_frame *tf, struct sched_task *td);
static i64 maybe_cancel_at_cancellation_point(struct trap_frame *tf,
                                              struct sched_task *td,
                                              i64 rc);

/* Copy a user-space path into kpath[257].  Returns the kernel str on success,
 * or sets *err to a negative errno and returns an empty str.
 */
static struct str copy_user_path(ptr upath, sz pathlen, char *kpath, i64 *err)
{
    if (pathlen <= 0 || pathlen > 256) {
        *err = -(i64) EINVAL;
        return (struct str) {0};
    }
    i64 rc = copy_from_user(kpath, upath, pathlen);
    if (rc < 0) {
        *err = rc;
        return (struct str) {0};
    }
    *err = 0;
    return str_new(kpath, pathlen);
}

/* Validate only the numeric fd range.  Open-state checks happen under
 * p->fd_lock at the callsite.
 */
static inline bool validate_fd_number(i32 fd)
{
    return fd >= 0 && fd < PROC_FD_MAX;
}

static i64 sys_exit(struct trap_frame *tf, struct sched_task *td)
{
    if (!td)
        return -(i64) EPERM;
    i32 code = (i32) tf->a0;
    struct proc *p = td->proc;
    u16 pid = p ? p->pid : 0;
    if (p)
        proc_exit(p, code);
    sched_set_task_state(td, TD_STATE_TERMINATING);
    pr_info(STR("process pid=%hu exited with code %d\n"), pid, code);
    return 0;
}

static i64 sys_write(struct trap_frame *tf, struct sched_task *td)
{
    i32 fd = (i32) tf->a0;
    ptr ubuf = (ptr) tf->a1;
    sz len = (sz) tf->a2;

    struct proc *p = td->proc;
    if (!p || !validate_fd_number(fd))
        return -(i64) EBADF;

    struct cap_ref ref = cap_lookup_fd(p, fd, CAP_RIGHT_WRITE);
    if (!ref.ptr)
        return cap_fd_is_valid(p, fd) ? -(i64) EACCES : -(i64) EBADF;
    struct fd_pool_entry *entry = ref.ptr;
    i64 rc;

    if (entry->kind == CAP_FD_KIND_PIPE) {
        struct pipe *pipe = entry->pipe;
        if (entry->pipe_read_end) {
            rc = -(i64) EBADF;
            goto out;
        }

        if (len <= 0) {
            rc = 0;
            goto out;
        }
        if (len > PIPE_BUF_SIZE)
            len = PIPE_BUF_SIZE;

        /* Copy the entire payload into a kernel buffer first, then hand
         * it to pipe_write as a single atomic call.  Splitting into
         * multiple pipe_write calls would let concurrent writers
         * interleave their data, breaking POSIX PIPE_BUF atomicity.
         */
        char kbuf[PIPE_BUF_SIZE];
        rc = copy_from_user(kbuf, ubuf, len);
        if (rc < 0)
            goto out;
        rc = pipe_write(pipe, kbuf, len);
        goto out;
    }

    if (len <= 0) {
        rc = 0;
        goto out;
    }
    if (len > 4096)
        len = 4096;

    if (entry->kind == CAP_FD_KIND_CONSOLE) {
        if (entry->console_id != PROC_FD_STDOUT &&
            entry->console_id != PROC_FD_STDERR) {
            rc = -(i64) EBADF;
            goto out;
        }
        char kbuf[256];
        sz total = 0;
        while (total < len) {
            sz chunk = len - total;
            if (chunk > (sz) sizeof(kbuf))
                chunk = (sz) sizeof(kbuf);
            rc = copy_from_user(kbuf, ubuf + total, chunk);
            if (rc < 0)
                goto out;
            print_str((struct str) {.dat = kbuf, .len = chunk});
            total += chunk;
        }
        rc = (i64) total;
        goto out;
    }

    char kbuf[256];
    sz total = 0;
    sz base_off = entry->offset;
    while (total < len) {
        sz chunk = len - total;
        if (chunk > (sz) sizeof(kbuf))
            chunk = (sz) sizeof(kbuf);
        rc = copy_from_user(kbuf, ubuf + total, chunk);
        if (rc < 0)
            goto out;
        struct byte_view bv = byte_view_new(kbuf, chunk);
        struct result_sz wres = vfs_write(&entry->file, bv, base_off + total);
        if (wres.is_error) {
            rc = -(i64) wres.code;
            goto out;
        }
        sz written = result_sz_checked(wres);
        if (written == 0)
            break;
        total += written;
    }
    entry->offset = base_off + total;
    rc = (i64) total;
out:
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_read(struct trap_frame *tf, struct sched_task *td)
{
    i32 fd = (i32) tf->a0;
    ptr ubuf = (ptr) tf->a1;
    sz len = (sz) tf->a2;

    struct proc *p = td->proc;
    if (!p || !validate_fd_number(fd))
        return -(i64) EBADF;

    struct cap_ref ref = cap_lookup_fd(p, fd, CAP_RIGHT_READ);
    if (!ref.ptr)
        return cap_fd_is_valid(p, fd) ? -(i64) EACCES : -(i64) EBADF;
    struct fd_pool_entry *entry = ref.ptr;
    i64 rc;

    if (entry->kind == CAP_FD_KIND_PIPE) {
        struct pipe *pipe = entry->pipe;
        if (!entry->pipe_read_end) {
            rc = -(i64) EBADF;
            goto out;
        }

        if (len <= 0) {
            rc = 0;
            goto out;
        }
        if (len > 4096)
            len = 4096;

        /* Validate the entire user buffer before consuming pipe bytes.
         * pipe_read advances the head irreversibly, so a late EFAULT
         * from copy_to_user would lose data from a non-seekable FD.
         * Must check writability (PTE_W), not just accessibility:
         * a read-only mapping passes user_addr_valid but faults on write.
         */
        if (!user_addr_writable(ubuf, len)) {
            rc = -(i64) EFAULT;
            goto out;
        }

        char kbuf[256];
        sz total = 0;
        while (total < len) {
            sz chunk = len - total;
            if (chunk > (sz) sizeof(kbuf))
                chunk = (sz) sizeof(kbuf);
            i64 got = pipe_read(pipe, kbuf, chunk);
            if (got < 0) {
                rc = total > 0 ? (i64) total : got;
                goto out;
            }
            if (got == 0)
                break;
            rc = copy_to_user(ubuf + total, kbuf, (sz) got);
            if (rc < 0) {
                rc = total > 0 ? (i64) total : rc;
                goto out;
            }
            total += (sz) got;
            if ((sz) got < chunk)
                break; /* short read: don't block again */
        }
        rc = (i64) total;
        goto out;
    }

    if (entry->kind == CAP_FD_KIND_CONSOLE) {
        rc = 0;
        goto out;
    }

    if (len <= 0) {
        rc = 0;
        goto out;
    }
    if (len > 4096)
        len = 4096;

    char kbuf[256];
    sz total = 0;
    sz base_off = entry->offset;
    while (total < len) {
        sz chunk = len - total;
        if (chunk > (sz) sizeof(kbuf))
            chunk = (sz) sizeof(kbuf);
        struct byte_buf bb = byte_buf_new(kbuf, 0, chunk);
        struct result_sz rres = vfs_read(&entry->file, &bb, base_off + total);
        if (rres.is_error) {
            rc = -(i64) rres.code;
            goto out;
        }
        sz got = result_sz_checked(rres);
        if (got == 0)
            break;
        rc = copy_to_user(ubuf + total, kbuf, got);
        if (rc < 0)
            goto out;
        total += got;
    }
    entry->offset = base_off + total;
    rc = (i64) total;
out:
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_open(struct trap_frame *tf, struct sched_task *td)
{
    ptr upath = (ptr) tf->a0;
    sz pathlen = (sz) tf->a1;

    struct proc *p = td->proc;
    if (!p)
        return -(i64) EPERM;

    if (cap_find_free_fd(p) < 0)
        return -(i64) EMFILE;

    i64 perr;
    char kpath[257];
    struct str path = copy_user_path(upath, pathlen, kpath, &perr);
    if (perr < 0)
        return perr;

    struct result_vfs_stat st = vfs_stat(path);
    if (st.is_error)
        return -(i64) st.code;
    struct vfs_stat vstat = result_vfs_stat_checked(st);
    /* GRANT is set only on system-minted FDs and on supervisor-opened FDs
     * explicitly flagged for delegation (e.g., SPAWN_FA_OPEN). Plain sys_open
     * mints a non-delegable cap.
     */
    u8 rights = CAP_RIGHT_READ;
    if ((vstat.flags & VFS_FLAG_RDONLY) == 0)
        rights |= CAP_RIGHT_WRITE;
    bool is_seekable = (vstat.flags & VFS_FLAG_NOSEEK) == 0;

    struct result_vfs_file fres = vfs_open(path);
    if (fres.is_error)
        return -(i64) fres.code;
    return (i64) cap_open_vfs(p, result_vfs_file_checked(fres), rights,
                              is_seekable, -1, false);
}

static i64 sys_close(struct trap_frame *tf, struct sched_task *td)
{
    i32 fd = (i32) tf->a0;

    struct proc *p = td->proc;
    if (!p || !validate_fd_number(fd))
        return -(i64) EBADF;

    return cap_close_fd(p, fd);
}

static i64 sys_stat(struct trap_frame *tf, struct sched_task *td)
{
    ptr upath = (ptr) tf->a0;
    sz pathlen = (sz) tf->a1;
    ptr ubuf = (ptr) tf->a2;

    (void) td;

    i64 perr;
    char kpath[257];
    struct str path = copy_user_path(upath, pathlen, kpath, &perr);
    if (perr < 0)
        return perr;

    struct result_vfs_stat st = vfs_stat(path);
    if (st.is_error)
        return -(i64) st.code;

    struct vfs_stat kstat = result_vfs_stat_checked(st);
    return copy_to_user(ubuf, &kstat, sizeof(kstat));
}

static i64 sys_yield(struct trap_frame *tf, struct sched_task *td)
{
    (void) tf;
    if (!td)
        return -(i64) EPERM;
    sched_set_task_state(td, TD_STATE_YIELDING);
    return 0;
}

static i64 sys_time(struct trap_frame *tf, struct sched_task *td)
{
    (void) tf;
    (void) td;
    return (i64) time_current_ms().ms;
}

/* Maximum binary size for sys_spawn (same as shell: 8 KiB). */
#define SPAWN_BUF_MAX 8192

/* Copy file actions array from user-space into kernel buffer.
 * For SPAWN_FA_OPEN actions, also copies the path string and replaces the
 * user pointer with the kernel pointer.  Returns 0 on success.
 */
static i64 copy_file_actions(ptr ufa_ptr,
                             sz fa_count,
                             struct spawn_file_action *kfa,
                             char (*kpaths)[SPAWN_FA_PATH_MAX])
{
    sz fa_size = fa_count * sizeof(struct spawn_file_action);
    i64 rc = copy_from_user(kfa, ufa_ptr, fa_size);
    if (rc < 0)
        return rc;

    for (sz i = 0; i < fa_count; i++) {
        if (kfa[i].type == SPAWN_FA_OPEN) {
            if (kfa[i].pathlen == 0 || kfa[i].pathlen > SPAWN_FA_PATH_MAX)
                return -(i64) EINVAL;
            rc = copy_from_user(kpaths[i], (ptr) kfa[i].path, kfa[i].pathlen);
            if (rc < 0)
                return rc;
            /* Replace user pointer with kernel pointer. */
            kfa[i].path = (u64) kpaths[i];
        }
    }
    return 0;
}

static i64 sys_spawn(struct trap_frame *tf, struct sched_task *td)
{
    ptr upath = (ptr) tf->a0;
    sz pathlen = (sz) tf->a1;
    ptr ufa_ptr = (ptr) tf->a2;   /* file_actions array, or 0 */
    sz fa_count = (sz) tf->a3;    /* number of file actions */
    ptr uattr_ptr = (ptr) tf->a4; /* spawn_attr pointer, or 0 */
    struct proc *parent = td->proc;

    /* Validate file action count early. */
    if (ufa_ptr && fa_count > SPAWN_FA_MAX)
        return -(i64) EINVAL;
    if (!ufa_ptr)
        fa_count = 0;

    /* Copy path from user-space. */
    i64 perr;
    char kpath[257];
    struct str path = copy_user_path(upath, pathlen, kpath, &perr);
    if (perr < 0)
        return perr;

    /* Copy file actions from user-space (if any). kpaths must outlive kfa
     * because copy_file_actions stores &kpaths[i] into kfa[i].path, which
     * is later dereferenced by spawn_apply_file_actions below.
     */
    struct spawn_file_action kfa[SPAWN_FA_MAX];
    char kpaths[SPAWN_FA_MAX][SPAWN_FA_PATH_MAX];
    if (fa_count > 0) {
        i64 fa_rc = copy_file_actions(ufa_ptr, fa_count, kfa, kpaths);
        if (fa_rc < 0)
            return fa_rc;
    }

    /* Copy spawn attributes from user-space (if any). */
    struct spawn_attr kattr;
    bool has_attr = false;
    if (uattr_ptr) {
        i64 attr_rc = copy_from_user(&kattr, uattr_ptr, sizeof(kattr));
        if (attr_rc < 0)
            return attr_rc;
        has_attr = true;
    }

    /* Validate: must be a regular file within size limit. */
    struct result_vfs_stat st = vfs_stat(path);
    if (st.is_error)
        return -(i64) st.code;
    struct vfs_stat kstat = result_vfs_stat_checked(st);
    if (kstat.type != VFS_TYPE_FILE)
        return -(i64) ENOEXEC;
    if (kstat.size == 0 || kstat.size > SPAWN_BUF_MAX)
        return -(i64) ENOEXEC;

    struct result_vfs_file fres = vfs_open(path);
    if (fres.is_error)
        return -(i64) fres.code;
    struct vfs_file f = result_vfs_file_checked(fres);

    /* Allocate a kernel buffer for the binary. */
    struct option_byte_array ba = kvalloc_alloc(SPAWN_BUF_MAX, 8);
    if (ba.is_none) {
        vfs_close(&f);
        return -(i64) ENOMEM;
    }
    struct byte_array buf_ba = option_byte_array_checked(ba);
    byte *buf = buf_ba.dat;

    struct byte_buf bb = byte_buf_new(buf, 0, SPAWN_BUF_MAX);
    struct result_sz rr = vfs_read(&f, &bb, 0);
    vfs_close(&f);

    if (rr.is_error) {
        kvalloc_free(buf_ba);
        return -(i64) rr.code;
    }
    sz nread = result_sz_checked(rr);
    if (nread == 0 || nread != kstat.size) {
        kvalloc_free(buf_ba);
        return -(i64) EIO;
    }

    /* Determine scheduling priority (default or from attr). */
    u8 child_prio = SCHED_PRIO_NORMAL;
    if (has_attr) {
        i32 attr_rc = spawn_apply_attr(NULL, &kattr, &child_prio);
        if (attr_rc < 0) {
            kvalloc_free(buf_ba);
            return (i64) attr_rc;
        }
    }

    /* Allocate child process. */
    struct proc *child = proc_alloc();
    if (!child) {
        kvalloc_free(buf_ba);
        return -(i64) ENOMEM;
    }
    child->parent_pid = parent->pid;
    child->parent_generation = parent->generation;

    /* Copy binary name into child proc. */
    sz namelen = pathlen < 31 ? pathlen : 31;
    for (sz i = 0; i < namelen; i++)
        child->name[i] = kpath[i];
    child->name[namelen] = '\0';

    /* Load binary: try ELF first, fall back to flat. */
    struct byte_view bv = byte_view_new(buf, nread);
    ptr entry;
    struct result lr;

    if (nread >= (sz) sizeof(struct elf64_hdr) &&
        elf64_is_valid((struct elf64_hdr *) buf)) {
        entry = ((struct elf64_hdr *) buf)->entry;
        /* Validate entry point is within the child's VA window. */
        if ((u64) entry < (u64) child->va_code_base ||
            (u64) entry >= (u64) child->va_stack_top) {
            kvalloc_free(buf_ba);
            proc_free(child);
            return -(i64) ENOEXEC;
        }
        lr = proc_load_elf(child, bv);
    } else {
        entry = (ptr) child->va_code_base;
        lr = proc_load_flat(child, bv);
    }
    if (lr.is_error) {
        kvalloc_free(buf_ba);
        proc_free(child);
        return -(i64) lr.code;
    }

    kvalloc_free(buf_ba);

    for (i32 fd = 0; fd < PROC_FD_MAX; fd++) {
        if (!cap_fd_is_valid(parent, fd))
            continue;
        i32 inherit_rc = cap_inherit_fd(parent, child, fd, fd);
        if (inherit_rc < 0) {
            proc_free(child);
            return (i64) inherit_rc;
        }
    }

    if (fa_count > 0) {
        i32 fa_rc = spawn_apply_file_actions(child, kfa, fa_count);
        if (fa_rc < 0) {
            proc_free(child);
            return (i64) fa_rc;
        }
    }

    /* Transition to RUNNING before enqueue: sched_create_user_task
     * enqueues the task immediately, so another CPU could schedule
     * and even terminate it before returning.  Setting RUNNING after
     * enqueue would corrupt a concurrent ZOMBIE transition.
     */
    proc_set_state(child, PROC_STATE_RUNNING);

    struct result tr = sched_create_user_task(child, entry, child_prio);
    if (tr.is_error) {
        proc_set_state(child, PROC_STATE_ZOMBIE);
        proc_free(child);
        return -(i64) tr.code;
    }
    pr_info(STR("sys_spawn: pid=%hu spawned \"%s\" as pid=%hu\n"),
            (u32) parent->pid, path, (u32) child->pid);
    return (i64) child->pid;
}

static i64 sys_wait(struct trap_frame *tf, struct sched_task *td)
{
    ptr ustatus = (ptr) tf->a0;
    struct proc *p = td->proc;

    u16 child_pid;
    i32 exit_code;
    i32 rc = proc_wait_child(p, &child_pid, &exit_code);
    if (rc < 0)
        return (i64) rc;

    /* Copy exit code to user-space if pointer is non-NULL. */
    if (ustatus) {
        i64 err = copy_to_user(ustatus, &exit_code, sizeof(exit_code));
        if (err < 0)
            return err;
    }
    return (i64) child_pid;
}

static i64 sys_getpid(struct trap_frame *tf, struct sched_task *td)
{
    (void) tf;
    struct proc *p = td->proc;
    return p ? (i64) p->pid : 0;
}

static i64 sys_getppid(struct trap_frame *tf, struct sched_task *td)
{
    (void) tf;
    struct proc *p = td->proc;
    return p ? (i64) p->parent_pid : 0;
}

static i64 sys_dup(struct trap_frame *tf, struct sched_task *td)
{
    i32 oldfd = (i32) tf->a0;
    struct proc *p = td->proc;
    if (!p || !validate_fd_number(oldfd))
        return -(i64) EBADF;
    return (i64) cap_dup_fd(p, oldfd, -1, false);
}

static i64 sys_dup2(struct trap_frame *tf, struct sched_task *td)
{
    i32 oldfd = (i32) tf->a0;
    i32 newfd = (i32) tf->a1;
    struct proc *p = td->proc;
    if (!p || !validate_fd_number(oldfd))
        return -(i64) EBADF;
    if (!validate_fd_number(newfd))
        return -(i64) EBADF;
    return (i64) cap_dup_fd(p, oldfd, newfd, true);
}

static i64 sys_lseek(struct trap_frame *tf, struct sched_task *td)
{
    i32 fd = (i32) tf->a0;
    i64 offset = (i64) tf->a1;
    i32 whence = (i32) tf->a2;

    struct proc *p = td->proc;
    if (!p || !validate_fd_number(fd))
        return -(i64) EBADF;

    struct cap_ref ref = cap_lookup_fd(p, fd, 0);
    if (!ref.ptr)
        return -(i64) EBADF;
    struct fd_pool_entry *entry = ref.ptr;
    i64 rc;
    if (!entry->is_seekable) {
        rc = -(i64) ESPIPE;
        goto out;
    }

    sz cur = entry->offset;
    sz new_off;

    switch (whence) {
    case SEEK_SET:
        if (offset < 0) {
            rc = -(i64) EINVAL;
            goto out;
        }
        new_off = (sz) offset;
        break;
    case SEEK_CUR: {
        u64 delta = (offset < 0) ? (u64) (-(offset + 1)) + 1 : (u64) offset;
        if (offset < 0 && delta > (u64) cur) {
            rc = -(i64) EINVAL;
            goto out;
        }
        if (offset > 0 && (u64) cur > (u64) (I64_MAX - offset)) {
            rc = -(i64) EINVAL;
            goto out;
        }
        new_off = cur + (sz) offset;
        break;
    }
    case SEEK_END:
        /* Needs vfs_file_size() - not yet available. */
        rc = -(i64) ENOSYS;
        goto out;
    default:
        rc = -(i64) EINVAL;
        goto out;
    }

    /* Guard: new_off must fit in i64 for the return value. */
    if (new_off > (sz) I64_MAX) {
        rc = -(i64) EINVAL;
        goto out;
    }

    entry->offset = new_off;
    rc = (i64) new_off;
out:
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_chdir(struct trap_frame *tf, struct sched_task *td)
{
    ptr upath = (ptr) tf->a0;
    sz pathlen = (sz) tf->a1;
    struct proc *p = td->proc;

    if (pathlen >= PROC_PATH_MAX)
        return -(i64) ENAMETOOLONG;

    i64 perr;
    char kpath[257];
    struct str path = copy_user_path(upath, pathlen, kpath, &perr);
    if (perr < 0)
        return perr;

    /* Verify the path exists and is a directory. */
    struct result_vfs_stat st = vfs_stat(path);
    if (st.is_error)
        return -(i64) st.code;
    struct vfs_stat kstat = result_vfs_stat_checked(st);
    if (kstat.type != VFS_TYPE_DIR)
        return -(i64) ENOTDIR;

    u64 fd_flags = proc_fd_lock_irqsave(p);
    memcpy(p->cwd, kpath, pathlen);
    p->cwd_len = pathlen;
    p->cwd[pathlen] = '\0';
    proc_fd_unlock_irqrestore(p, fd_flags);
    return 0;
}

static inline bool futex_addr_valid(ptr uaddr)
{
    if ((u64) uaddr % sizeof(u32) != 0)
        return false;
    uptr ua = (uptr) uaddr;
    return ua >= (uptr) USER_CODE_BASE &&
           ua <= (uptr) USER_STACK_TOP - sizeof(u32);
}

static i64 sys_futex(struct trap_frame *tf, struct sched_task *td)
{
    (void) td;
    ptr uaddr = (ptr) tf->a0;
    i32 op = (i32) tf->a1;
    u32 val = (u32) tf->a2;

    if (!futex_addr_valid(uaddr))
        return -(i64) EINVAL;

    switch (op) {
    case FUTEX_WAIT:
        return maybe_cancel_at_cancellation_point(tf, td,
                                                  futex_wait(uaddr, val));
    case FUTEX_WAKE:
        return futex_wake(uaddr, val);
    case FUTEX_CMP_REQUEUE: {
        ptr uaddr2 = (ptr) tf->a3;
        u32 nr_requeue = (u32) tf->a4;
        if (!futex_addr_valid(uaddr2))
            return -(i64) EINVAL;
        return futex_cmp_requeue(uaddr, val, uaddr2, 1, nr_requeue);
    }
    case FUTEX_LOCK_PI:
        return maybe_cancel_at_cancellation_point(tf, td, futex_lock_pi(uaddr));
    case FUTEX_UNLOCK_PI:
        return futex_unlock_pi(uaddr);
    default:
        return -(i64) EINVAL;
    }
}

static i64 sys_getcwd(struct trap_frame *tf, struct sched_task *td)
{
    ptr ubuf = (ptr) tf->a0;
    sz size = (sz) tf->a1;
    struct proc *p = td->proc;
    char cwd[PROC_PATH_MAX];
    sz needed;

    /* POSIX: size must accommodate the path plus a NUL terminator. */
    u64 fd_flags = proc_fd_lock_irqsave(p);
    needed = p->cwd_len + 1;
    if (size < needed) {
        proc_fd_unlock_irqrestore(p, fd_flags);
        return -(i64) ERANGE;
    }
    memcpy(cwd, p->cwd, needed);
    proc_fd_unlock_irqrestore(p, fd_flags);

    i64 rc = copy_to_user(ubuf, cwd, needed);
    if (rc < 0)
        return rc;
    return (i64) needed;
}

static i64 sys_pipe(struct trap_frame *tf, struct sched_task *td)
{
    ptr ufds = (ptr) tf->a0;
    struct proc *p = td->proc;

    struct pipe *pipe = pipe_alloc();
    if (!pipe)
        return -(i64) ENOMEM;

    i32 rfd = cap_open_pipe(p, pipe, true, CAP_RIGHT_READ | CAP_RIGHT_GRANT, -1,
                            false);
    if (rfd < 0) {
        pipe_close_read(pipe);
        pipe_close_write(pipe);
        return rfd;
    }
    i32 wfd = cap_open_pipe(p, pipe, false, CAP_RIGHT_WRITE | CAP_RIGHT_GRANT,
                            -1, false);
    if (wfd < 0) {
        proc_close_fd(p, rfd);
        pipe_close_write(pipe);
        return wfd;
    }

    /* Copy FD pair to user-space: fds[0] = read, fds[1] = write. */
    i32 kfds[2] = {rfd, wfd};
    i64 rc = copy_to_user(ufds, kfds, sizeof(kfds));
    if (rc < 0) {
        /* Undo: close both FDs. */
        proc_close_fd(p, rfd);
        proc_close_fd(p, wfd);
        return rc;
    }
    return 0;
}

i64 sys_sysconf_query(i64 name)
{
    switch (name) {
    case _SC_PAGE_SIZE:
        return (i64) PAGE_SIZE;
    case _SC_OPEN_MAX:
        return (i64) PROC_FD_MAX;
    case _SC_NPROCESSORS_CONF: /* fall through */
    case _SC_NPROCESSORS_ONLN:
        return (i64) nr_cpus_online;
    case _SC_PIPE_BUF:
        return (i64) PIPE_BUF_SIZE;
    case _SC_CHILD_MAX:
        return (i64) (PROC_MAX - 1); /* minus one for the parent */
    case _SC_MEMLOCK:
        return 0; /* all memory is resident; locking is implicit */
    /* PSE51 option reporting: present features return their _POSIX_*
     * value, absent features return -1.  See docs/pse51-matrix.md.
     */
    case _SC_TIMERS:
        return (i64) _POSIX_TIMERS;
    case _SC_MONOTONIC_CLOCK:
        return (i64) _POSIX_MONOTONIC_CLOCK;
    case _SC_PRIORITY_SCHEDULING:
        return (i64) _POSIX_PRIORITY_SCHEDULING;
    case _SC_SEMAPHORES:
        return (i64) _POSIX_SEMAPHORES;
    case _SC_BARRIERS:
        return (i64) _POSIX_BARRIERS;
    case _SC_READER_WRITER_LOCKS:
        return (i64) _POSIX_READER_WRITER_LOCKS;
    case _SC_THREAD_PRIORITY_INHERIT:
        return (i64) _POSIX_THREAD_PRIO_INHERIT;
    case _SC_MESSAGE_PASSING:
        return (i64) _POSIX_MESSAGE_PASSING;
    case _SC_THREADS:
        return (i64) _POSIX_THREADS;
    case _SC_THREAD_CPUTIME:
        return (i64) _POSIX_THREAD_CPUTIME;
    case _SC_CPUTIME:
        return (i64) _POSIX_CPUTIME;
    case _SC_REALTIME_SIGNALS:
        return (i64) _POSIX_REALTIME_SIGNALS;
    case _SC_SPIN_LOCKS: /* fall through; userspace surface absent */
    case _SC_CLOCK_SELECTION:
        return -1; /* feature not implemented (POSIX-style negative reply) */
    default:
        return -(i64) EINVAL;
    }
}

/* sysconf(name): return system configuration values.
 * a0 = _SC_ name constant.  Returns the value or -EINVAL.
 */
static i64 sys_sysconf(struct trap_frame *tf, struct sched_task *td __unused)
{
    return sys_sysconf_query((i64) tf->a0);
}

/* sched_setaffinity(pid, affinity): set CPU affinity for a task.
 * a0 = pid (0 = self), a1 = affinity (-1 = any, >= 0 = pinned hart).
 * Returns 0 on success, -EINVAL for invalid hart/args, -ESRCH for bad pid.
 *
 * After storing the new affinity, sends a reschedule IPI to the hart
 * where the task last ran so the scheduler re-evaluates placement.
 */
static i64 sys_sched_setaffinity(struct trap_frame *tf, struct sched_task *td)
{
    /* Validate full register width before narrowing. */
    i64 raw_pid = (i64) tf->a0;
    i64 raw_aff = (i64) tf->a1;

    if (raw_pid < 0 || raw_pid > (i64) U16_MAX)
        return -(i64) EINVAL;
    if (raw_aff < -1 || raw_aff > (i64) I32_MAX)
        return -(i64) EINVAL;

    u16 pid = (u16) raw_pid;
    i32 affinity = (i32) raw_aff;

    /* Validate affinity: -1 (any) or valid hart index. */
    if (affinity != -1 && (u32) affinity >= nr_cpus_online)
        return -(i64) EINVAL;

    struct sched_task *target;

    if (pid == 0) {
        if (!td || !td->proc)
            return -(i64) EPERM;
        target = td;
        __atomic_store_n(&target->td_affinity, affinity, __ATOMIC_RELEASE);
    } else {
        /* Hold proc_table_lock across find + affinity write to prevent
         * proc_exit() from detaching the leader concurrently. Once
         * pthread_create lands, "set affinity by PID" still targets the
         * thread-group leader (POSIX sched_setaffinity semantics).
         */
        u64 pflags = proc_table_lock_irqsave();
        struct proc *p = proc_find_locked(pid);
        struct sched_task *leader = proc_thread_group_leader(p);
        if (!leader) {
            proc_table_unlock_irqrestore(pflags);
            return -(i64) ESRCH;
        }
        target = leader;
        __atomic_store_n(&target->td_affinity, affinity, __ATOMIC_RELEASE);
#if CONFIG_SMP
        u32 last_cpu = target->td_last_cpu;
#endif
        proc_table_unlock_irqrestore(pflags);
#if CONFIG_SMP
        if (last_cpu < MAX_CPUS && last_cpu != get_cpuid())
            ipi_send(last_cpu, IPI_SCHED);
#endif
        return 0;
    }

#if CONFIG_SMP
    {
        u32 last_cpu = target->td_last_cpu;
        if (last_cpu < MAX_CPUS && last_cpu != get_cpuid())
            ipi_send(last_cpu, IPI_SCHED);
        else
            __atomic_store_n(&get_pcpu()->need_resched, 1, __ATOMIC_RELEASE);
    }
#endif

    return 0;
}

/* sched_getaffinity(pid, uptr): get CPU affinity for a task.
 * a0 = pid (0 = self), a1 = user pointer to i32 result.
 * Returns 0 on success, copies affinity to *a1.
 * Returns -ESRCH for bad pid, -EFAULT for bad pointer, -EINVAL for bad args.
 *
 * Affinity is written to user memory to avoid ambiguity with -1 (any hart)
 * and negative errno values in the syscall return.
 */
static i64 sys_sched_getaffinity(struct trap_frame *tf, struct sched_task *td)
{
    i64 raw_pid = (i64) tf->a0;
    ptr uptr_out = (ptr) tf->a1;

    if (raw_pid < 0 || raw_pid > (i64) U16_MAX)
        return -(i64) EINVAL;

    u16 pid = (u16) raw_pid;
    i32 result;

    if (pid == 0) {
        if (!td || !td->proc)
            return -(i64) EPERM;
        result = __atomic_load_n(&td->td_affinity, __ATOMIC_ACQUIRE);
    } else {
        u64 pflags = proc_table_lock_irqsave();
        struct proc *p = proc_find_locked(pid);
        struct sched_task *leader = proc_thread_group_leader(p);
        if (!leader) {
            proc_table_unlock_irqrestore(pflags);
            return -(i64) ESRCH;
        }
        result = __atomic_load_n(&leader->td_affinity, __ATOMIC_ACQUIRE);
        proc_table_unlock_irqrestore(pflags);
    }

    return copy_to_user(uptr_out, &result, sizeof(result));
}

#if CONFIG_SCHED_DEADLINE
/* sched_setattr(uattr): set scheduling policy and parameters.
 * a0 = user pointer to struct sched_attr.
 * Returns 0 on success, -EINVAL/-EBUSY/-EFAULT on failure.
 */
static i64 sys_sched_setattr(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;

    ptr uattr = (ptr) tf->a0;
    struct sched_attr kattr;
    i64 rc = copy_from_user(&kattr, uattr, sizeof(kattr));
    if (rc < 0)
        return rc;

    if (kattr.policy == SCHED_POLICY_NORMAL) {
        sched_dl_clearattr(td);
        return 0;
    }
    if (kattr.policy != SCHED_POLICY_DEADLINE)
        return -(i64) EINVAL;

    return (i64) sched_dl_setattr(td, kattr.runtime_ns, kattr.deadline_ns,
                                  kattr.period_ns);
}

/* sched_getattr(uattr): get current scheduling policy and parameters.
 * a0 = user pointer to struct sched_attr (output).
 * Returns 0 on success, -EFAULT on bad pointer.
 */
static u64 ticks_to_ns(u64 ticks, u64 freq)
{
    return (ticks / freq) * 1000000000ULL +
           ((ticks % freq) * 1000000000ULL) / freq;
}

static i64 sys_sched_getattr(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;

    ptr uattr = (ptr) tf->a0;
    struct sched_attr kattr = {0};

#if CONFIG_SCHED_DEADLINE
    kattr.policy = td->td_policy;
    if (td->td_policy == SCHED_POLICY_DEADLINE && td->dl.dl_active) {
        u64 freq = time_get_timebase_freq();
        if (freq > 0) {
            kattr.runtime_ns = ticks_to_ns(td->dl.dl_runtime, freq);
            kattr.deadline_ns = ticks_to_ns(td->dl.dl_deadline, freq);
            kattr.period_ns = ticks_to_ns(td->dl.dl_period, freq);
        }
    }
#endif

    return copy_to_user(uattr, &kattr, sizeof(kattr));
}
#endif /* CONFIG_SCHED_DEADLINE */

/* SYS_SET_ROBUST_LIST: register the user-space robust futex list for
 * the calling thread. Stored per-task because each thread holds its
 * own locks and unwinds its own list on exit (Linux semantics).
 * a0 = pointer to robust_list_head (first entry / self = empty)
 * a1 = byte offset from entry pointer to the futex word
 * a2 = pointer to the pending entry (0 if none)
 */
static i64 sys_set_robust_list(struct trap_frame *tf, struct sched_task *td)
{
    if (!td)
        return -(i64) EPERM;
    ptr head = (ptr) tf->a0;
    i32 offset = (i32) tf->a1;
    ptr pending = (ptr) tf->a2;

    /* Validate alignment: the head must be pointer-aligned (the list is
     * a linked list of pointers), and the futex offset must yield a
     * u32-aligned address when applied to any entry.
     */
    if (head && ((uptr) head & (sizeof(ptr) - 1)))
        return -(i64) EINVAL;
    if (pending && ((uptr) pending & (sizeof(ptr) - 1)))
        return -(i64) EINVAL;
    if (offset & (i32) (sizeof(u32) - 1))
        return -(i64) EINVAL;

    td->td_robust_list_head = head;
    td->td_robust_futex_offset = offset;
    td->td_robust_pending = pending;
    return 0;
}

/* SYS_GET_ROBUST_LIST: retrieve the calling thread's robust list
 * registration.
 * a0 = user pointer to store the head pointer (ptr *)
 * a1 = user pointer to store the futex offset (i32 *)
 * a2 = user pointer to store the pending pointer (ptr *)
 */
static i64 sys_get_robust_list(struct trap_frame *tf, struct sched_task *td)
{
    if (!td)
        return -(i64) EPERM;
    ptr u_head = (ptr) tf->a0;
    ptr u_offset = (ptr) tf->a1;
    ptr u_pending = (ptr) tf->a2;
    i64 rc;

    rc = copy_to_user(u_head, &td->td_robust_list_head,
                      sizeof(td->td_robust_list_head));
    if (rc < 0)
        return -(i64) EFAULT;
    rc = copy_to_user(u_offset, &td->td_robust_futex_offset,
                      sizeof(td->td_robust_futex_offset));
    if (rc < 0)
        return -(i64) EFAULT;
    rc = copy_to_user(u_pending, &td->td_robust_pending,
                      sizeof(td->td_robust_pending));
    if (rc < 0)
        return -(i64) EFAULT;
    return 0;
}

/* --- PSE51 clock and nanosleep (item 15) --- */

/* Sum cpu_time_us across every thread of the calling proc. Caller
 * must hold proc_table_lock so the tasks[] view is stable.
 */
static u64 proc_cputime_us_locked(struct proc *p)
{
    if (!p)
        return 0;
    u64 sum = p->exited_cpu_time_us;
    u64 now_ticks = time_rdtime();
    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        struct sched_task *t = p->tasks[i];
        if (t) {
            sum += t->cpu_time_us;
            if (t->state == TD_STATE_RUNNING && now_ticks >= t->switch_in_ticks)
                sum += time_ticks_to_us(now_ticks - t->switch_in_ticks);
        }
    }
    return sum;
}

static i64 cancel_thread_now(struct trap_frame *tf, struct sched_task *td)
{
    if (!td)
        return -(i64) EPERM;
    tf->a0 = (u64) -ECANCELED;
    tf->a7 = SYS_THREAD_EXIT;
    return syscall_dispatch(tf, td);
}

static i64 maybe_cancel_at_cancellation_point(struct trap_frame *tf,
                                              struct sched_task *td,
                                              i64 rc)
{
    if (rc == -(i64) ECANCELED && thread_cancel_enabled_pending(td))
        return cancel_thread_now(tf, td);
    return rc;
}

static i64 sys_clock_gettime(struct trap_frame *tf, struct sched_task *td)
{
    i32 clk_id = (i32) tf->a0;
    ptr u_ts = (ptr) tf->a1;

    if (clk_id != CLOCK_MONOTONIC && clk_id != CLOCK_REALTIME &&
        clk_id != CLOCK_PROCESS_CPUTIME_ID && clk_id != CLOCK_THREAD_CPUTIME_ID)
        return -(i64) EINVAL;

    struct timespec ts;
    if (clk_id == CLOCK_THREAD_CPUTIME_ID) {
        if (!td)
            return -(i64) EPERM;
        u64 us = td->cpu_time_us;
        u64 now_ticks = time_rdtime();
        if (td->state == TD_STATE_RUNNING && now_ticks >= td->switch_in_ticks)
            us += time_ticks_to_us(now_ticks - td->switch_in_ticks);
        ts.tv_sec = (i64) (us / 1000000ULL);
        ts.tv_nsec = (i64) ((us % 1000000ULL) * (u64) NSEC_PER_USEC);
    } else if (clk_id == CLOCK_PROCESS_CPUTIME_ID) {
        if (!td || !td->proc)
            return -(i64) EPERM;
        u64 pflags = proc_table_lock_irqsave();
        u64 us = proc_cputime_us_locked(td->proc);
        proc_table_unlock_irqrestore(pflags);
        ts.tv_sec = (i64) (us / 1000000ULL);
        ts.tv_nsec = (i64) ((us % 1000000ULL) * (u64) NSEC_PER_USEC);
    } else {
        u64 ticks = time_rdtime();
        u64 freq = time_get_timebase_freq();
        if (freq == 0)
            return -(i64) EIO;
        ts.tv_sec = (i64) (ticks / freq);
        ts.tv_nsec = (i64) ((ticks % freq) * NSEC_PER_SEC / freq);
    }

    i64 rc = copy_to_user(u_ts, &ts, sizeof(ts));
    if (rc < 0)
        return rc;
    return 0;
}

static i64 sys_clock_getres(struct trap_frame *tf,
                            struct sched_task *td __unused)
{
    i32 clk_id = (i32) tf->a0;
    ptr u_ts = (ptr) tf->a1;

    if (clk_id != CLOCK_MONOTONIC && clk_id != CLOCK_REALTIME &&
        clk_id != CLOCK_PROCESS_CPUTIME_ID && clk_id != CLOCK_THREAD_CPUTIME_ID)
        return -(i64) EINVAL;

    u64 freq = time_get_timebase_freq();
    if (freq == 0)
        return -(i64) EIO;

    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = (i64) (NSEC_PER_SEC / freq);
    if (ts.tv_nsec == 0)
        ts.tv_nsec = 1;

    if (u_ts) {
        i64 rc = copy_to_user(u_ts, &ts, sizeof(ts));
        if (rc < 0)
            return rc;
    }
    return 0;
}

static i64 sys_nanosleep(struct trap_frame *tf, struct sched_task *td)
{
    ptr u_req = (ptr) tf->a0;
    ptr u_rem = (ptr) tf->a1;

    struct timespec req;
    i64 rc = copy_from_user(&req, u_req, sizeof(req));
    if (rc < 0)
        return rc;

    if (req.tv_sec < 0 || req.tv_nsec < 0 || req.tv_nsec >= NSEC_PER_SEC)
        return -(i64) EINVAL;

    /* Bound user-controlled tv_sec so neither the ns nor ms conversion
     * can wrap u64. U64_MAX / NSEC_PER_SEC is ~18.4 billion seconds, so
     * the cap loses no real sleep request and protects against a caller
     * passing tv_sec near INT64_MAX (which would otherwise wrap req_ns
     * and silently turn a multi-decade sleep into a near-zero one).
     */
    if ((u64) req.tv_sec > U64_MAX / (u64) NSEC_PER_SEC)
        return -(i64) EINVAL;

    /* Capture the requested duration in raw ticks so the remainder we
     * report on EINTR is precise to the timebase, not rounded to the
     * scheduler's millisecond grain. The kernel still sleeps in ms units
     * because that is what callout_set_ticks expects via sleep_ms.
     */
    u64 freq = time_get_timebase_freq();
    if (freq == 0)
        return -(i64) EIO;
    u64 req_ns = (u64) req.tv_sec * (u64) NSEC_PER_SEC + (u64) req.tv_nsec;
    u64 ms = (u64) req.tv_sec * 1000 + (u64) req.tv_nsec / NSEC_PER_MSEC;
    if (ms == 0 && req.tv_nsec > 0)
        ms = 1; /* sub-millisecond: round up to one tick */

    if (thread_cancel_enabled_pending(td))
        return cancel_thread_now(tf, td);

    u64 t0 = time_rdtime();
    sleep_ms(time_ms_new(ms));
    u64 elapsed_ticks = time_rdtime() - t0;
    u64 elapsed_ns = (elapsed_ticks / freq) * (u64) NSEC_PER_SEC +
                     ((elapsed_ticks % freq) * (u64) NSEC_PER_SEC) / freq;

    /* On early wakeup by a signal, report EINTR and (when rem is
     * non-NULL) write back the unexpired remainder. The trap exit
     * path will deliver the signal. The remainder must be reported
     * by the kernel: a libc shim cannot reconstruct it accurately
     * if the thread is preempted between syscall return and the
     * shim's clock read, which would silently violate RT deadlines.
     *
     * signal_has_deliverable uses atomic loads, matching the rest
     * of the kernel's lockless fast-path read of sig_state. A raw
     * struct read here is a data race against signal_send /
     * signal_deliver.
     *
     * The remainder write is best-effort: a bad rem pointer must
     * not mask the EINTR return because the dominant fact is that
     * the sleep was interrupted. Returning EINTR rather than EFAULT
     * keeps user-space retry loops on the right errno.
     */
    if (thread_cancel_enabled_pending(td))
        return cancel_thread_now(tf, td);

    if (td && signal_has_deliverable(td) && elapsed_ns < req_ns) {
        if (u_rem) {
            u64 rem_ns = req_ns - elapsed_ns;
            struct timespec rem = {
                .tv_sec = (i64) (rem_ns / (u64) NSEC_PER_SEC),
                .tv_nsec = (i64) (rem_ns % (u64) NSEC_PER_SEC),
            };
            i64 cprc __unused = copy_to_user(u_rem, &rem, sizeof(rem));
        }
        return -(i64) EINTR;
    }

    /* Normal completion: POSIX/Linux leave *rem unmodified. */
    return 0;
}

/* --- PSE51 memory locking: no-ops on bare metal --- */

static i64 sys_mlockall(struct trap_frame *tf __unused,
                        struct sched_task *td __unused)
{
    return 0;
}

static i64 sys_munlockall(struct trap_frame *tf __unused,
                          struct sched_task *td __unused)
{
    return 0;
}

/* mlock(addr, len) / munlock(addr, len): PSE51 requires the range form
 * even when memory is permanently resident. The kernel validates the
 * range overlaps user space, then returns success without touching any
 * page-table state.  EINVAL on zero length or addr+len overflow,
 * matching POSIX (Linux returns EINVAL for empty / wrap).
 */
static i64 sys_mlock_munlock_common(ptr addr, sz len)
{
    if (len == 0)
        return -(i64) EINVAL;
    if ((uptr) addr > (uptr) (U64_MAX - (u64) len))
        return -(i64) EINVAL;
    if (!user_addr_valid(addr, len))
        return -(i64) ENOMEM;
    return 0;
}

static i64 sys_mlock(struct trap_frame *tf, struct sched_task *td __unused)
{
    return sys_mlock_munlock_common((ptr) tf->a0, (sz) tf->a1);
}

static i64 sys_munlock(struct trap_frame *tf, struct sched_task *td __unused)
{
    return sys_mlock_munlock_common((ptr) tf->a0, (sz) tf->a1);
}

/* fsync(fd) / fdatasync(fd): PSE51 mandates _POSIX_FSYNC. The
 * disk-backed SFS already commits writes synchronously internally
 * (see kernel/fs/sfs.c); the synthetic and RAM filesystems have no
 * backing store. Validate the FD is open, reject pipe FDs (POSIX
 * specifies EINVAL for file types that do not support synchronized
 * I/O, matching Linux), return success.
 */
static i64 sys_fsync_common(struct sched_task *td, i32 fd)
{
    struct proc *p = td ? td->proc : NULL;
    if (!p || !validate_fd_number(fd))
        return -(i64) EBADF;
    if (!cap_fd_is_valid(p, fd))
        return -(i64) EBADF;
    if (cap_fd_is_pipe(p, fd))
        return -(i64) EINVAL;
    return 0;
}

static i64 sys_fsync(struct trap_frame *tf, struct sched_task *td)
{
    return sys_fsync_common(td, (i32) tf->a0);
}

static i64 sys_fdatasync(struct trap_frame *tf, struct sched_task *td)
{
    return sys_fsync_common(td, (i32) tf->a0);
}

/* --- PSE51 synchronization syscalls (item 15a) --- */

static i64 sys_mutex_init_h(struct trap_frame *tf __unused,
                            struct sched_task *td __unused)
{
    i32 object_index = sync_mutex_alloc(td->proc);
    if (object_index < 0)
        return (i64) object_index;
    i32 handle = cap_open_handle(td->proc, (u16) object_index, CAP_TYPE_MUTEX,
                                 CAP_RIGHT_WRITE, -1, false);
    if (handle < 0) {
        sync_mutex_put_idx(object_index);
        return (i64) handle;
    }
    return (i64) handle;
}

static i64 sys_mutex_lock_h(struct trap_frame *tf,
                            struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_MUTEX);
    if (!ref.type)
        return -(i64) EINVAL;
    i64 rc;
    struct pi_mutex *mtx = sync_mutex_get((i32) ref.object_index);
    if (!mtx) {
        rc = -(i64) EINVAL;
        goto out;
    }
    if (thread_cancel_enabled_pending(td)) {
        rc = cancel_thread_now(tf, td);
        goto out;
    }
    rc = maybe_cancel_at_cancellation_point(
        tf, td, (i64) pi_mutex_lock_interruptible(mtx));
out:
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_mutex_trylock_h(struct trap_frame *tf,
                               struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_MUTEX);
    if (!ref.type)
        return -(i64) EINVAL;
    struct pi_mutex *mtx = sync_mutex_get((i32) ref.object_index);
    i64 rc = mtx ? (i64) pi_mutex_trylock(mtx) : -(i64) EINVAL;
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_mutex_unlock_h(struct trap_frame *tf,
                              struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_MUTEX);
    if (!ref.type)
        return -(i64) EINVAL;
    struct pi_mutex *mtx = sync_mutex_get((i32) ref.object_index);
    if (!mtx) {
        cap_put_ref(&ref);
        return -(i64) EINVAL;
    }
    pi_mutex_unlock(mtx);
    cap_put_ref(&ref);
    return 0;
}

static i64 sys_cond_init_h(struct trap_frame *tf __unused,
                           struct sched_task *td __unused)
{
    i32 object_index = sync_condvar_alloc(td->proc);
    if (object_index < 0)
        return (i64) object_index;
    i32 handle = cap_open_handle(td->proc, (u16) object_index, CAP_TYPE_CONDVAR,
                                 CAP_RIGHT_WRITE, -1, false);
    if (handle < 0) {
        sync_condvar_put_idx(object_index);
        return (i64) handle;
    }
    return (i64) handle;
}

static i64 sys_cond_wait_h(struct trap_frame *tf,
                           struct sched_task *td __unused)
{
    i32 cv_h = (i32) tf->a0;
    i32 mtx_h = (i32) tf->a1;
    struct cap_ref cv_ref =
        cap_lookup_object(td->proc, cv_h, CAP_RIGHT_WRITE, CAP_TYPE_CONDVAR);
    if (!cv_ref.type)
        return -(i64) EINVAL;
    struct cap_ref mtx_ref =
        cap_lookup_object(td->proc, mtx_h, CAP_RIGHT_WRITE, CAP_TYPE_MUTEX);
    if (!mtx_ref.type) {
        cap_put_ref(&cv_ref);
        return -(i64) EINVAL;
    }
    i64 rc;
    struct condvar *cv = sync_condvar_get((i32) cv_ref.object_index);
    struct pi_mutex *mtx = sync_mutex_get((i32) mtx_ref.object_index);
    if (!cv || !mtx) {
        rc = -(i64) EINVAL;
        goto out;
    }
    if (thread_cancel_enabled_pending(td)) {
        rc = cancel_thread_now(tf, td);
        goto out;
    }
    rc =
        maybe_cancel_at_cancellation_point(tf, td, (i64) condvar_wait(cv, mtx));
out:
    cap_put_ref(&mtx_ref);
    cap_put_ref(&cv_ref);
    return rc;
}

/* Convert an absolute CLOCK_MONOTONIC timespec (in user space) to a
 * relative time_ms suitable for the kernel timed-wait primitives.
 *
 * On success returns 0 and writes the relative timeout to *out_ms.
 * Returns -EINVAL for malformed timespec, -EFAULT for a bad user
 * pointer, -ETIMEDOUT if the deadline has already passed (the
 * caller should short-circuit immediately rather than enter a
 * zero-length wait that would block forever on some primitives).
 *
 * Rationale: pushing this conversion into a libc shim is racy under
 * preemption: a thread reading clock_gettime in user space, then
 * subtracting and entering the kernel, can be preempted between the
 * two and silently miss its deadline. Doing the conversion at the
 * syscall entry gives a tighter window (a few instructions) and
 * matches POSIX semantics for absolute timed waits.
 */
/* Convert a user-supplied absolute timespec on the named clock to a
 * relative time_ms suitable for the kernel's monotonic timed-wait
 * primitives.  Today CLOCK_MONOTONIC and CLOCK_REALTIME share the
 * same epoch, so the conversion is identity; the clk_id parameter
 * is plumbed so adding a real RTC offset later is a one-place change
 * rather than a silent semantic break for every caller.  Returns 0
 * on success, -ETIMEDOUT if the deadline already passed,
 * -EINVAL / -EFAULT / -EIO on bad input.
 */
static i64 timed_wait_abs_to_rel(i32 clk_id,
                                 ptr u_abs_ts,
                                 struct time_ms *out_ms)
{
    if (clk_id != CLOCK_MONOTONIC && clk_id != CLOCK_REALTIME)
        return -(i64) EINVAL;

    if (!u_abs_ts) {
        *out_ms = time_ms_new(TIME_MS_MAX);
        return 0;
    }
    struct timespec abs;
    i64 rc = copy_from_user(&abs, u_abs_ts, sizeof(abs));
    if (rc < 0)
        return rc;
    if (abs.tv_sec < 0 || abs.tv_nsec < 0 || abs.tv_nsec >= NSEC_PER_SEC)
        return -(i64) EINVAL;

    u64 freq = time_get_timebase_freq();
    if (freq == 0)
        return -(i64) EIO;
    u64 now_ticks = time_rdtime();
    u64 now_sec = now_ticks / freq;
    u64 now_nsec = (now_ticks % freq) * (u64) NSEC_PER_SEC / freq;

    /* CLOCK_REALTIME translation hook: today the realtime clock is
     * anchored to the same monotonic ticks, so no offset is applied.
     * If/when a real wall-clock offset lands, subtract it here for
     * CLOCK_REALTIME and translate the user deadline back into the
     * monotonic timebase.
     */
    (void) clk_id; /* placeholder; see comment above */

    if ((u64) abs.tv_sec < now_sec ||
        ((u64) abs.tv_sec == now_sec && (u64) abs.tv_nsec <= now_nsec))
        return -(i64) ETIMEDOUT;

    u64 diff_sec = (u64) abs.tv_sec - now_sec;
    i64 diff_nsec = abs.tv_nsec - (i64) now_nsec;
    if (diff_nsec < 0) {
        diff_sec -= 1;
        diff_nsec += NSEC_PER_SEC;
    }
    if (diff_sec > TIME_MS_MAX / 1000ULL) {
        *out_ms = time_ms_new(TIME_MS_MAX);
        return 0;
    }
    u64 ms = diff_sec * 1000ULL + (u64) diff_nsec / (u64) NSEC_PER_MSEC;
    if (((u64) diff_nsec % (u64) NSEC_PER_MSEC) != 0)
        ms += 1;
    *out_ms = time_ms_new(ms);
    return 0;
}

static i64 sys_cond_timedwait_h(struct trap_frame *tf,
                                struct sched_task *td __unused)
{
    i32 cv_h = (i32) tf->a0;
    i32 mtx_h = (i32) tf->a1;
    ptr u_abs_ts = (ptr) tf->a2;
    struct time_ms timeout;
    i64 rc = timed_wait_abs_to_rel(CLOCK_REALTIME, u_abs_ts, &timeout);
    if (rc < 0)
        return rc;
    struct cap_ref cv_ref =
        cap_lookup_object(td->proc, cv_h, CAP_RIGHT_WRITE, CAP_TYPE_CONDVAR);
    if (!cv_ref.type)
        return -(i64) EINVAL;
    struct cap_ref mtx_ref =
        cap_lookup_object(td->proc, mtx_h, CAP_RIGHT_WRITE, CAP_TYPE_MUTEX);
    if (!mtx_ref.type) {
        cap_put_ref(&cv_ref);
        return -(i64) EINVAL;
    }
    struct condvar *cv = sync_condvar_get((i32) cv_ref.object_index);
    struct pi_mutex *mtx = sync_mutex_get((i32) mtx_ref.object_index);
    if (!cv || !mtx) {
        rc = -(i64) EINVAL;
        goto out;
    }
    if (thread_cancel_enabled_pending(td)) {
        rc = cancel_thread_now(tf, td);
        goto out;
    }
    rc = maybe_cancel_at_cancellation_point(
        tf, td, (i64) condvar_wait_timeout(cv, mtx, timeout));
out:
    cap_put_ref(&mtx_ref);
    cap_put_ref(&cv_ref);
    return rc;
}

static i64 sys_cond_signal_h(struct trap_frame *tf,
                             struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_CONDVAR);
    if (!ref.type)
        return -(i64) EINVAL;
    struct condvar *cv = sync_condvar_get((i32) ref.object_index);
    if (cv)
        condvar_signal(cv);
    cap_put_ref(&ref);
    return cv ? 0 : -(i64) EINVAL;
}

static i64 sys_cond_broadcast_h(struct trap_frame *tf,
                                struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_CONDVAR);
    if (!ref.type)
        return -(i64) EINVAL;
    struct condvar *cv = sync_condvar_get((i32) ref.object_index);
    if (cv)
        condvar_broadcast(cv);
    cap_put_ref(&ref);
    return cv ? 0 : -(i64) EINVAL;
}

static i64 sys_sem_init_h(struct trap_frame *tf, struct sched_task *td __unused)
{
    i32 initial = (i32) tf->a0;
    i32 object_index = sync_sem_alloc(td->proc, initial);
    if (object_index < 0)
        return (i64) object_index;
    i32 handle =
        cap_open_handle(td->proc, (u16) object_index, CAP_TYPE_SEMAPHORE,
                        CAP_RIGHT_WRITE, -1, false);
    if (handle < 0) {
        sync_sem_put_idx(object_index);
        return (i64) handle;
    }
    return (i64) handle;
}

static i64 sys_sem_wait_h(struct trap_frame *tf, struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref = cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE,
                                           CAP_TYPE_SEMAPHORE);
    if (!ref.type)
        return -(i64) EINVAL;
    i64 rc;
    struct semaphore *s = sync_sem_get((i32) ref.object_index);
    if (!s) {
        rc = -(i64) EINVAL;
        goto out;
    }
    if (thread_cancel_enabled_pending(td)) {
        rc = cancel_thread_now(tf, td);
        goto out;
    }
    rc = maybe_cancel_at_cancellation_point(tf, td,
                                            (i64) sem_wait_interruptible(s));
out:
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_sem_trywait_h(struct trap_frame *tf,
                             struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref = cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE,
                                           CAP_TYPE_SEMAPHORE);
    if (!ref.type)
        return -(i64) EINVAL;
    struct semaphore *s = sync_sem_get((i32) ref.object_index);
    i64 rc = s ? (i64) sem_trywait(s) : -(i64) EINVAL;
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_sem_post_h(struct trap_frame *tf, struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref = cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE,
                                           CAP_TYPE_SEMAPHORE);
    if (!ref.type)
        return -(i64) EINVAL;
    struct semaphore *s = sync_sem_get((i32) ref.object_index);
    if (s)
        sem_post(s);
    cap_put_ref(&ref);
    return s ? 0 : -(i64) EINVAL;
}

static i64 sys_sem_timedwait_h(struct trap_frame *tf,
                               struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    ptr u_abs_ts = (ptr) tf->a1;
    struct time_ms timeout;
    i64 rc = timed_wait_abs_to_rel(CLOCK_REALTIME, u_abs_ts, &timeout);
    if (rc < 0)
        return rc;
    struct cap_ref ref = cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE,
                                           CAP_TYPE_SEMAPHORE);
    if (!ref.type)
        return -(i64) EINVAL;
    struct semaphore *s = sync_sem_get((i32) ref.object_index);
    if (!s) {
        rc = -(i64) EINVAL;
        goto out;
    }
    if (thread_cancel_enabled_pending(td)) {
        rc = cancel_thread_now(tf, td);
        goto out;
    }
    rc = maybe_cancel_at_cancellation_point(tf, td,
                                            (i64) sem_timedwait(s, timeout));
out:
    cap_put_ref(&ref);
    return rc;
}

/* --- POSIX barriers (item 15i) --- */

static i64 sys_barrier_init_h(struct trap_frame *tf,
                              struct sched_task *td __unused)
{
    u32 count = (u32) tf->a0;
    i32 object_index = sync_barrier_alloc(td->proc, count);
    if (object_index < 0)
        return (i64) object_index;
    i32 handle = cap_open_handle(td->proc, (u16) object_index, CAP_TYPE_BARRIER,
                                 CAP_RIGHT_WRITE, -1, false);
    if (handle < 0) {
        sync_barrier_put_idx(object_index);
        return (i64) handle;
    }
    return (i64) handle;
}

static i64 sys_barrier_wait_h(struct trap_frame *tf,
                              struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_BARRIER);
    if (!ref.type)
        return -(i64) EINVAL;
    i64 rc;
    struct barrier *b = sync_barrier_get((i32) ref.object_index);
    if (!b) {
        rc = -(i64) EINVAL;
        goto out;
    }
    if (thread_cancel_enabled_pending(td)) {
        rc = cancel_thread_now(tf, td);
        goto out;
    }
    rc = maybe_cancel_at_cancellation_point(
        tf, td, (i64) barrier_wait_interruptible(b));
out:
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_barrier_destroy_h(struct trap_frame *tf,
                                 struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    /* Pin across barrier_destroy so a concurrent destroy cannot free the
     * pool entry while we still operate on the primitive.
     */
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_BARRIER);
    if (!ref.type)
        return -(i64) EINVAL;
    struct cap_slot_view slot = cap_slot_read(td->proc, handle);
    struct barrier *b = sync_barrier_get((i32) ref.object_index);
    if (!b || !slot.valid) {
        cap_put_ref(&ref);
        return -(i64) EINVAL;
    }
    i32 rc = barrier_destroy(b);
    cap_put_ref(&ref);
    if (rc == 0)
        return cap_drop_token(td->proc, cap_make_handle(&slot));
    return (i64) rc;
}

/* --- POSIX rwlocks (item 15j) --- */

static i64 sys_rwlock_init_h(struct trap_frame *tf __unused,
                             struct sched_task *td __unused)
{
    i32 object_index = sync_rwlock_alloc(td->proc);
    if (object_index < 0)
        return (i64) object_index;
    i32 handle = cap_open_handle(td->proc, (u16) object_index, CAP_TYPE_RWLOCK,
                                 CAP_RIGHT_WRITE, -1, false);
    if (handle < 0) {
        sync_rwlock_put_idx(object_index);
        return (i64) handle;
    }
    return (i64) handle;
}

static i64 sys_rwlock_rdlock_h(struct trap_frame *tf,
                               struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_RWLOCK);
    if (!ref.type)
        return -(i64) EINVAL;
    i64 rc;
    struct rwlock *rw = sync_rwlock_get((i32) ref.object_index);
    if (!rw) {
        rc = -(i64) EINVAL;
        goto out;
    }
    if (thread_cancel_enabled_pending(td)) {
        rc = cancel_thread_now(tf, td);
        goto out;
    }
    rc = maybe_cancel_at_cancellation_point(
        tf, td, (i64) rwlock_rdlock_interruptible(rw));
out:
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_rwlock_wrlock_h(struct trap_frame *tf,
                               struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_RWLOCK);
    if (!ref.type)
        return -(i64) EINVAL;
    i64 rc;
    struct rwlock *rw = sync_rwlock_get((i32) ref.object_index);
    if (!rw) {
        rc = -(i64) EINVAL;
        goto out;
    }
    if (thread_cancel_enabled_pending(td)) {
        rc = cancel_thread_now(tf, td);
        goto out;
    }
    rc = maybe_cancel_at_cancellation_point(
        tf, td, (i64) rwlock_wrlock_interruptible(rw));
out:
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_rwlock_tryrdlock_h(struct trap_frame *tf,
                                  struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_RWLOCK);
    if (!ref.type)
        return -(i64) EINVAL;
    struct rwlock *rw = sync_rwlock_get((i32) ref.object_index);
    i64 rc = rw ? (i64) rwlock_tryrdlock(rw) : -(i64) EINVAL;
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_rwlock_trywrlock_h(struct trap_frame *tf,
                                  struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_RWLOCK);
    if (!ref.type)
        return -(i64) EINVAL;
    struct rwlock *rw = sync_rwlock_get((i32) ref.object_index);
    i64 rc = rw ? (i64) rwlock_trywrlock(rw) : -(i64) EINVAL;
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_rwlock_unlock_h(struct trap_frame *tf,
                               struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_RWLOCK);
    if (!ref.type)
        return -(i64) EINVAL;
    struct rwlock *rw = sync_rwlock_get((i32) ref.object_index);
    if (rw)
        rwlock_unlock(rw);
    cap_put_ref(&ref);
    return rw ? 0 : -(i64) EINVAL;
}

static i64 sys_rwlock_timedrdlock_h(struct trap_frame *tf,
                                    struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    ptr u_abs_ts = (ptr) tf->a1;
    struct time_ms timeout;
    i64 rc = timed_wait_abs_to_rel(CLOCK_REALTIME, u_abs_ts, &timeout);
    if (rc < 0)
        return rc;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_RWLOCK);
    if (!ref.type)
        return -(i64) EINVAL;
    struct rwlock *rw = sync_rwlock_get((i32) ref.object_index);
    if (!rw) {
        rc = -(i64) EINVAL;
        goto out;
    }
    if (thread_cancel_enabled_pending(td)) {
        rc = cancel_thread_now(tf, td);
        goto out;
    }
    rc = maybe_cancel_at_cancellation_point(
        tf, td, (i64) rwlock_timedrdlock(rw, timeout));
out:
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_rwlock_timedwrlock_h(struct trap_frame *tf,
                                    struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    ptr u_abs_ts = (ptr) tf->a1;
    struct time_ms timeout;
    i64 rc = timed_wait_abs_to_rel(CLOCK_REALTIME, u_abs_ts, &timeout);
    if (rc < 0)
        return rc;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_RWLOCK);
    if (!ref.type)
        return -(i64) EINVAL;
    struct rwlock *rw = sync_rwlock_get((i32) ref.object_index);
    if (!rw) {
        rc = -(i64) EINVAL;
        goto out;
    }
    if (thread_cancel_enabled_pending(td)) {
        rc = cancel_thread_now(tf, td);
        goto out;
    }
    rc = maybe_cancel_at_cancellation_point(
        tf, td, (i64) rwlock_timedwrlock(rw, timeout));
out:
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_rwlock_destroy_h(struct trap_frame *tf,
                                struct sched_task *td __unused)
{
    i32 handle = (i32) tf->a0;
    /* Pin across rwlock_destroy: a concurrent destroy must not free the
     * pool entry under us.
     */
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_RWLOCK);
    if (!ref.type)
        return -(i64) EINVAL;
    struct cap_slot_view slot = cap_slot_read(td->proc, handle);
    struct rwlock *rw = sync_rwlock_get((i32) ref.object_index);
    if (!rw || !slot.valid) {
        cap_put_ref(&ref);
        return -(i64) EINVAL;
    }
    i32 rc = rwlock_destroy(rw);
    cap_put_ref(&ref);
    if (rc == 0)
        return cap_drop_token(td->proc, cap_make_handle(&slot));
    return (i64) rc;
}

/* --- POSIX message queues (item 15b) --- */

static i64 sys_mq_open(struct trap_frame *tf, struct sched_task *td)
{
    u32 max_msgs = (u32) tf->a0;
    sz max_msg_size = (sz) tf->a1;
    struct proc *p = td ? td->proc : NULL;
    i32 object_index = mqueue_open(p, max_msgs, max_msg_size);
    if (object_index < 0)
        return (i64) object_index;
    i32 handle = cap_open_handle(p, (u16) object_index, CAP_TYPE_MQUEUE,
                                 CAP_RIGHT_READ | CAP_RIGHT_WRITE, -1, false);
    if (handle < 0) {
        (void) mqueue_close(object_index);
        return (i64) handle;
    }
    return (i64) handle;
}

static i64 sys_mq_close(struct trap_frame *tf, struct sched_task *td)
{
    i32 handle = (i32) tf->a0;
    struct cap_slot_view slot;
    if (!cap_lookup_slot(td->proc, handle, 0, CAP_TYPE_MQUEUE, &slot))
        return -(i64) EINVAL;
    return cap_drop_token(td->proc, cap_make_handle(&slot));
}

static i64 sys_mq_send(struct trap_frame *tf, struct sched_task *td)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_WRITE, CAP_TYPE_MQUEUE);
    if (!ref.type)
        return -(i64) EINVAL;
    ptr u_msg = (ptr) tf->a1;
    sz len = (sz) tf->a2;
    u32 priority = (u32) tf->a3;
    i64 rc;

    if (len <= 0 || len > MQ_MAX_MSG_SIZE) {
        rc = -(i64) EMSGSIZE;
        goto out;
    }

    u8 kbuf[MQ_MAX_MSG_SIZE];
    rc = copy_from_user(kbuf, u_msg, len);
    if (rc < 0)
        goto out;

    if (thread_cancel_enabled_pending(td)) {
        rc = cancel_thread_now(tf, td);
        goto out;
    }
    rc = maybe_cancel_at_cancellation_point(
        tf, td, (i64) mqueue_send((i32) ref.object_index, kbuf, len, priority));
out:
    cap_put_ref(&ref);
    return rc;
}

/* Shared receive body for sys_mq_{receive,timedreceive}. timed selects
 * mqueue_timedreceive (which honors timeout); plain selects mqueue_receive
 * (blocks indefinitely). On entry, ref is the pinned mqueue cap; the
 * caller releases it on return.
 */
static i64 mq_receive_common(struct trap_frame *tf,
                             struct sched_task *td,
                             struct cap_ref *ref,
                             ptr u_buf,
                             sz buf_size,
                             ptr u_prio,
                             bool timed,
                             struct time_ms timeout)
{
    if (buf_size <= 0 || buf_size > MQ_MAX_MSG_SIZE)
        return -(i64) EINVAL;

    if (thread_cancel_enabled_pending(td))
        return cancel_thread_now(tf, td);

    u8 kbuf[MQ_MAX_MSG_SIZE];
    u32 prio = 0;
    i32 ret =
        timed ? mqueue_timedreceive((i32) ref->object_index, kbuf, buf_size,
                                    &prio, timeout)
              : mqueue_receive((i32) ref->object_index, kbuf, buf_size, &prio);
    if (ret < 0)
        return maybe_cancel_at_cancellation_point(tf, td, (i64) ret);

    i64 rc = copy_to_user(u_buf, kbuf, (sz) ret);
    if (rc < 0)
        return rc;
    if (u_prio) {
        rc = copy_to_user(u_prio, &prio, sizeof(prio));
        if (rc < 0)
            return rc;
    }
    return (i64) ret;
}

static i64 sys_mq_receive(struct trap_frame *tf, struct sched_task *td)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_READ, CAP_TYPE_MQUEUE);
    if (!ref.type)
        return -(i64) EINVAL;
    i64 rc = mq_receive_common(tf, td, &ref, (ptr) tf->a1, (sz) tf->a2,
                               (ptr) tf->a3, false, (struct time_ms) {0});
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_mq_timedreceive(struct trap_frame *tf, struct sched_task *td)
{
    i32 handle = (i32) tf->a0;
    struct cap_ref ref =
        cap_lookup_object(td->proc, handle, CAP_RIGHT_READ, CAP_TYPE_MQUEUE);
    if (!ref.type)
        return -(i64) EINVAL;
    struct time_ms timeout;
    i64 rc = timed_wait_abs_to_rel(CLOCK_REALTIME, (ptr) tf->a4, &timeout);
    if (rc < 0) {
        cap_put_ref(&ref);
        return rc;
    }
    rc = mq_receive_common(tf, td, &ref, (ptr) tf->a1, (sz) tf->a2,
                           (ptr) tf->a3, true, timeout);
    cap_put_ref(&ref);
    return rc;
}

/* --- PSE51 scheduling syscalls (item 17) --- */

static i64 sys_sched_get_priority_min(struct trap_frame *tf __unused,
                                      struct sched_task *td __unused)
{
    return (i64) SCHED_PRIO_IDLE;
}

static i64 sys_sched_get_priority_max(struct trap_frame *tf __unused,
                                      struct sched_task *td __unused)
{
    return (i64) (CONFIG_SCHED_NPRIO - 1);
}

static i64 sys_sched_yield_pse51(struct trap_frame *tf __unused,
                                 struct sched_task *td)
{
    if (!td)
        return -(i64) EPERM;
    sched_set_task_state(td, TD_STATE_YIELDING);
    return 0;
}

static i64 sys_sched_setparam(struct trap_frame *tf, struct sched_task *td)
{
    if (!td)
        return -(i64) EPERM;

    i32 new_prio = (i32) tf->a0;
    if (new_prio < SCHED_PRIO_IDLE || new_prio >= CONFIG_SCHED_NPRIO)
        return -(i64) EINVAL;

    /* Cannot raise above caller's own base priority (privilege bound). */
    if ((u8) new_prio > td->td_base_prio)
        return -(i64) EPERM;

    td->td_base_prio = (u8) new_prio;
    pi_mutex_refresh_prio(td);
    return 0;
}

static i64 sys_sched_getparam(struct trap_frame *tf __unused,
                              struct sched_task *td)
{
    if (!td)
        return -(i64) EPERM;
    return (i64) td->td_base_prio;
}

/* --- Signals (item 16) --- */

static i64 sys_kill_h(struct trap_frame *tf, struct sched_task *td __unused)
{
    u16 pid = (u16) tf->a0;
    i32 signo = (i32) tf->a1;

    struct proc *target = proc_find(pid);
    if (!target)
        return -(i64) ESRCH;

    if (signo == 0)
        return 0; /* existence check only */

    return (i64) signal_send(target, signo);
}

static i64 sys_sigqueue_h(struct trap_frame *tf, struct sched_task *td __unused)
{
    u16 pid = (u16) tf->a0;
    i32 signo = (i32) tf->a1;
    u64 value = tf->a2;

    struct proc *target = proc_find(pid);
    if (!target)
        return -(i64) ESRCH;

    if (signo == 0)
        return 0;

    return (i64) signal_queue_send(target, signo, value);
}

/* Forward declaration; defined alongside the other thread syscalls
 * later in the file.
 */
static bool thread_lookup_cap(struct proc *p,
                              u64 handle,
                              u8 required_rights,
                              struct cap_slot_view *out)
{
    return cap_lookup_token(p, handle, required_rights, CAP_TYPE_THREAD, out);
}

static struct sched_task *thread_from_cap_locked(
    struct proc *p,
    const struct cap_slot_view *slot)
{
    if (!p || !slot || slot->object_index >= PROC_THREAD_MAX)
        return NULL;
    struct sched_task *target = p->tasks[slot->object_index];
    if (!target || target->td_cap_slot != (i16) slot->slot_index)
        return NULL;
    return target;
}

static bool thread_target_is_live(const struct sched_task *target);

/* pthread_kill: thread-directed signal delivery within the calling
 * proc. Differs from kill(): the bit lands on a specific thread's
 * td_sig.pending rather than the per-proc proc_pending mask, so the
 * signal targets exactly that thread. Unknown thread handle -> ESRCH; signo==0
 * is an existence check. SIGKILL is process-wide by definition and
 * is rejected with EINVAL since pthread_kill targeting a single
 * thread cannot meaningfully forward it.
 */
static i64 sys_pthread_kill_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    u64 handle = tf->a0;
    i32 signo = (i32) tf->a1;
    struct proc *p = td->proc;

    if (signo < 0 || signo >= SIG_MAX)
        return -(i64) EINVAL;
    if (signo == SIGKILL)
        return -(i64) EINVAL;

    struct cap_slot_view cap_slot;
    if (!thread_lookup_cap(p, handle, CAP_RIGHT_WRITE, &cap_slot))
        return -(i64) ESRCH;

    u64 tflags = proc_table_lock_irqsave();
    struct sched_task *target = thread_from_cap_locked(p, &cap_slot);
    if (!thread_target_is_live(target)) {
        proc_table_unlock_irqrestore(tflags);
        return -(i64) ESRCH;
    }
    if (signo != 0) {
        u64 sflags = proc_sig_lock_irqsave(p);
        __atomic_or_fetch(&target->td_sig.pending, sig_bit(signo),
                          __ATOMIC_RELAXED);
        proc_sig_unlock_irqrestore(p, sflags);
        if (target->state == TD_STATE_SLEEPING)
            sched_wake_sleeping(target);
    }
    proc_table_unlock_irqrestore(tflags);
    return 0;
}

/* pthread_sigmask: identical wire shape to SYS_SIGPROCMASK. Both
 * operate on the calling thread's td_sig.blocked. Exposed under a
 * separate syscall number so userspace libc can keep
 * pthread_sigmask and sigprocmask as distinct ABI surfaces, even
 * though Mazu's storage is already per-thread.
 */
static i64 sys_sigprocmask_h(struct trap_frame *tf, struct sched_task *td);
static i64 sys_pthread_sigmask_h(struct trap_frame *tf, struct sched_task *td)
{
    return sys_sigprocmask_h(tf, td);
}

/* sigsuspend(set):
 *   replace td_sig.blocked with *set, sleep until a non-masked
 *   signal becomes deliverable, then return -EINTR. POSIX
 *   requires the pre-call mask to be restored before user space
 *   resumes; signal_deliver / SIG_IGN handle that via
 *   td_sig.sigsuspend_saved_blocked, so the mask is NOT restored
 *   here. If trap exit finds that another thread consumed the
 *   pending bit before this thread reaches return-to-user,
 *   signal_deliver still restores the saved mask via
 *   sigsuspend_active.
 *   a0 = user pointer to u32 set.
 */
static i64 sys_sigsuspend_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    ptr u_set = (ptr) tf->a0;
    if (!u_set)
        return -(i64) EFAULT;
    u32 new_mask;
    i64 rc = copy_from_user(&new_mask, u_set, sizeof(new_mask));
    if (rc < 0)
        return rc;
    /* SIGKILL must not be blocked. */
    new_mask &= ~sig_bit(SIGKILL);

    struct proc *p = td->proc;
    u64 sflags = proc_sig_lock_irqsave(p);
    td->td_sig.sigsuspend_saved_blocked = td->td_sig.blocked;
    td->td_sig.sigsuspend_active = true;
    td->td_sig.blocked = new_mask;
    proc_sig_unlock_irqrestore(p, sflags);

    /* Park in TD_STATE_SLEEPING with a maximal duration so the
     * scheduler does not loop the runqueue burning CPU. signal_send
     * calls signal_interrupt_task -> sched_wake_sleeping when a
     * signal arrives, which short-circuits the sleep.
     */
    while (!signal_has_deliverable(td))
        sleep_ms(time_ms_new(TIME_MS_MAX));

    return -(i64) EINTR;
}

/* sigtimedwait(set, info, timeout, value_out):
 *   block until any signal in *set becomes pending; on success,
 *   atomically dequeue that signal (without invoking its handler) and
 *   write its number to *info. If a queued sigqueue payload exists for
 *   that signo, the kernel writes it to *value_out. Plain kill-style
 *   signals report no payload and leave *value_out unmodified.
 *   Returns the signal number on success, or -EAGAIN on timeout,
 *   -EINTR if a non-set signal arrives.
 *   a0 = user *u32 set, a1 = user *i32 signo_out (NULL ok),
 *   a2 = user *struct timespec timeout (NULL = wait forever),
 *   a3 = user *u64 value_out (NULL ok).
 */
static i64 sys_sigtimedwait_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    ptr u_set = (ptr) tf->a0;
    ptr u_signo_out = (ptr) tf->a1;
    ptr u_timeout = (ptr) tf->a2;
    ptr u_value_out = (ptr) tf->a3;

    if (!u_set)
        return -(i64) EFAULT;
    u32 set;
    i64 rc = copy_from_user(&set, u_set, sizeof(set));
    if (rc < 0)
        return rc;
    /* SIGKILL is never wait-dequeueable; mask it out. */
    set &= ~sig_bit(SIGKILL);
    if (set == 0)
        return -(i64) EINVAL;

    /* Pre-validate u_signo_out before dequeuing the signal. A bad
     * pointer must NOT cause the bit to be cleared and then the
     * signal lost via -EFAULT; once dequeued the signal cannot be
     * delivered to a handler.
     */
    if (u_signo_out && !user_addr_writable(u_signo_out, sizeof(i32)))
        return -(i64) EFAULT;
    if (u_value_out && !user_addr_writable(u_value_out, sizeof(u64)))
        return -(i64) EFAULT;

    /* Compute a monotonic deadline once. NULL timeout = no deadline.
     * Bound tv_sec so the (tv_sec * freq) and (now + add_ticks)
     * computations cannot wrap u64 and silently turn a long timeout
     * into an immediate one.
     */
    bool have_deadline = (u_timeout != 0);
    u64 deadline_ticks = 0;
    u64 timeout_ms = TIME_MS_MAX;
    if (have_deadline) {
        struct timespec ts;
        rc = copy_from_user(&ts, u_timeout, sizeof(ts));
        if (rc < 0)
            return rc;
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= NSEC_PER_SEC)
            return -(i64) EINVAL;
        u64 freq = time_get_timebase_freq();
        if (freq == 0)
            return -(i64) EIO;
        /* tv_sec * freq must not overflow u64. */
        if ((u64) ts.tv_sec > U64_MAX / freq)
            return -(i64) EINVAL;
        u64 add_ticks = (u64) ts.tv_sec * freq +
                        ((u64) ts.tv_nsec * freq) / (u64) NSEC_PER_SEC;
        u64 now = time_rdtime();
        if (add_ticks > U64_MAX - now)
            deadline_ticks = U64_MAX;
        else
            deadline_ticks = now + add_ticks;
        /* Compute the matching ms timeout for sleep_ms.  Round up
         * sub-ms remainders so the wait is at least the requested
         * duration.
         */
        u64 ms =
            (u64) ts.tv_sec * 1000ULL + (u64) ts.tv_nsec / (u64) NSEC_PER_MSEC;
        if (((u64) ts.tv_nsec % (u64) NSEC_PER_MSEC) != 0)
            ms += 1;
        timeout_ms = ms;
    }

    struct proc *p = td->proc;

    /* Tell signal_send-style writers what set this thread is parked
     * on, so a non-matching signal does not need to interrupt the
     * sleep. signal_interrupt_task still wakes for matching signals
     * (its sleep is woken by sched_wake_sleeping).
     */
    u64 sflags = proc_sig_lock_irqsave(p);
    td->td_sig.sigwait_set = set;
    proc_sig_unlock_irqrestore(p, sflags);

    i64 result = 0;
    i32 dequeued_signo = 0;
    u64 dequeued_value = 0;
    bool dequeued_has_value = false;
    bool dequeued_from_proc = false;
    for (;;) {
        sflags = proc_sig_lock_irqsave(p);
        u32 thread_pending = td->td_sig.pending;
        u32 proc_pending = p->sig_state.proc_pending;
        u32 candidate = (thread_pending | proc_pending) & set;
        if (candidate != 0) {
            i32 signo = 0;
            for (i32 i = 1; i < SIG_MAX; i++) {
                if (candidate & sig_bit(i)) {
                    signo = i;
                    break;
                }
            }
            if (thread_pending & sig_bit(signo))
                td->td_sig.pending &= ~sig_bit(signo);
            else if (!signal_claim_proc_pending_locked(
                         p, signo, &dequeued_value, &dequeued_has_value)) {
                td->td_sig.sigwait_set = 0;
                proc_sig_unlock_irqrestore(p, sflags);
                continue;
            } else
                dequeued_from_proc = true;
            td->td_sig.sigwait_set = 0;
            proc_sig_unlock_irqrestore(p, sflags);
            dequeued_signo = signo;
            result = (i64) signo;
            break;
        }
        /* Out-of-set unblocked signal -> -EINTR per POSIX. */
        u32 deliverable_other =
            (thread_pending | proc_pending) & ~td->td_sig.blocked & ~set;
        if (deliverable_other != 0) {
            td->td_sig.sigwait_set = 0;
            proc_sig_unlock_irqrestore(p, sflags);
            return -(i64) EINTR;
        }
        proc_sig_unlock_irqrestore(p, sflags);

        if (have_deadline) {
            u64 now = time_rdtime();
            if (now >= deadline_ticks) {
                sflags = proc_sig_lock_irqsave(p);
                td->td_sig.sigwait_set = 0;
                proc_sig_unlock_irqrestore(p, sflags);
                return -(i64) EAGAIN;
            }
            /* Sleep for the remaining time; signal_send will wake
             * the sleep via signal_interrupt_task -> sched_wake_
             * sleeping when a deliverable signal arrives.
             */
            u64 remaining = deadline_ticks - now;
            u64 freq = time_get_timebase_freq();
            u64 rem_ms = remaining / (freq / 1000ULL ? freq / 1000ULL : 1);
            if (rem_ms == 0)
                rem_ms = 1;
            sleep_ms(time_ms_new(rem_ms));
        } else {
            sleep_ms(time_ms_new(timeout_ms));
        }
    }

    /* Write the signo out-of-line. u_signo_out was pre-validated so
     * a fault here is unlikely; if it does fault (concurrent munmap
     * after validation), restore the pending instance so the caller can
     * retry. signal_restore_proc_pending_locked re-checks queue capacity
     * under sig_lock, since a concurrent sigqueue may have arrived after
     * the original pop and filled the queue.
     */
    if (u_signo_out) {
        i64 cprc =
            copy_to_user(u_signo_out, &dequeued_signo, sizeof(dequeued_signo));
        if (cprc < 0) {
            sflags = proc_sig_lock_irqsave(p);
            if (dequeued_from_proc) {
                (void) signal_restore_proc_pending_locked(
                    p, dequeued_signo, dequeued_value, dequeued_has_value);
            } else {
                td->td_sig.pending |= sig_bit(dequeued_signo);
            }
            proc_sig_unlock_irqrestore(p, sflags);
            return cprc;
        }
    }
    if (u_value_out && dequeued_has_value) {
        i64 cprc =
            copy_to_user(u_value_out, &dequeued_value, sizeof(dequeued_value));
        if (cprc < 0) {
            sflags = proc_sig_lock_irqsave(p);
            if (dequeued_from_proc) {
                (void) signal_restore_proc_pending_locked(
                    p, dequeued_signo, dequeued_value, dequeued_has_value);
            } else {
                td->td_sig.pending |= sig_bit(dequeued_signo);
            }
            proc_sig_unlock_irqrestore(p, sflags);
            return cprc;
        }
    }
    return result;
}

static i64 sys_sigaction_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;

    i32 signo = (i32) tf->a0;
    sig_handler_fn_t handler = (sig_handler_fn_t) (uptr) tf->a1;
    u32 sa_mask = (u32) tf->a2;

    if (signo <= 0 || signo >= SIG_MAX || signo == SIGKILL)
        return -(i64) EINVAL;

    struct proc *p = td->proc;
    u64 flags = proc_sig_lock_irqsave(p);
    sig_handler_fn_t old = p->sig_state.actions[signo].handler;
    p->sig_state.actions[signo].handler = handler;
    p->sig_state.actions[signo].sa_mask = sa_mask;
    proc_sig_unlock_irqrestore(p, flags);

    return (i64) (uptr) old;
}

static i64 sys_sigreturn_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    return (i64) signal_return(td, tf);
}

/* sigprocmask(how, new, old): operates on the calling thread's blocked
 * mask (per-task td_sig.blocked since the per-thread state migration).
 * Today PROC_THREAD_MAX == 1 so this is observably indistinguishable
 * from a per-process mask, but the storage is already per-thread; once
 * pthread_create lands, this remains the right ABI for pthread_sigmask.
 * SIGKILL cannot be blocked, matching POSIX.
 */
static i64 sys_sigprocmask_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    i32 how = (i32) tf->a0;
    ptr u_set = (ptr) tf->a1;
    ptr u_old = (ptr) tf->a2;
    struct proc *p = td->proc;

    u32 set = 0;
    bool have_set = u_set != 0;
    if (have_set && how != SIG_BLOCK && how != SIG_UNBLOCK &&
        how != SIG_SETMASK)
        return -(i64) EINVAL;
    if (have_set) {
        i64 rc = copy_from_user(&set, u_set, sizeof(set));
        if (rc < 0)
            return rc;
    }

    /* POSIX: "If sigprocmask() fails, the signal mask of the process
     * shall not be changed." Pre-validate the user out pointer before
     * mutating kernel state so a bad u_old does not leave the mask in
     * a half-applied state.
     */
    if (u_old && !user_addr_writable(u_old, sizeof(u32)))
        return -(i64) EFAULT;

    u64 flags = proc_sig_lock_irqsave(p);
    u32 old = td->td_sig.blocked;
    if (have_set) {
        u32 new_mask;
        switch (how) {
        case SIG_BLOCK:
            new_mask = old | set;
            break;
        case SIG_UNBLOCK:
            new_mask = old & ~set;
            break;
        default: /* SIG_SETMASK */
            new_mask = set;
            break;
        }
        /* SIGKILL cannot be blocked. Mask the bit even if user asked. */
        new_mask &= ~sig_bit(SIGKILL);
        td->td_sig.blocked = new_mask;
    }
    proc_sig_unlock_irqrestore(p, flags);

    if (u_old) {
        /* Pre-validated above, so this should not fault; surface any
         * residual error rather than papering over it because the mask
         * change is already committed and cannot be undone here.
         */
        i64 rc = copy_to_user(u_old, &old, sizeof(old));
        if (rc < 0)
            return rc;
    }
    return 0;
}

/* --- Thread management (item 15d) --- */

/* PSE51 user threads.  PROC_THREAD_MAX bounds the per-process task
 * list; sched_create_user_thread allocates a new task in the calling
 * proc, runs it on its own per-thread stack inside the proc VA
 * window, and returns the CAP_TYPE_THREAD slot index. Lifecycle:
 *
 *   create  -> JOINABLE
 *   detach  -> DETACHED  (no one will join; auto-cleans on exit)
 *   exit    -> EXITED    (waiting for join, or auto-reaped if detached)
 *   join    -> REAPED    (joiner has consumed the exit code)
 *
 * The per-process disposition table, FD table, signal disposition,
 * and timer ownership stay on struct proc; per-thread state
 * (sig pending/blocked, signal-frame chain, robust futex,
 * exit_code, join waitqueue) lives on struct sched_task.
 */
static i64 sys_thread_create_common(struct trap_frame *tf,
                                    struct sched_task *td,
                                    bool use_explicit_prio_abi)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    ptr u_entry = (ptr) tf->a0;
    ptr u_arg = (ptr) tf->a1;
    u8 creator_base_prio = __atomic_load_n(&td->td_base_prio, __ATOMIC_RELAXED);
    u8 prio = creator_base_prio;
    if (use_explicit_prio_abi) {
        /* Priority encoding in a2:
         *   0                          -> inherit creator's base priority.
         *   1..CONFIG_SCHED_NPRIO      -> explicit (prio = a2 - 1).
         *   anything else              -> EINVAL.
         *
         * This lives on a dedicated syscall number so the historical
         * SYS_THREAD_CREATE ABI remains a strict two-argument interface.
         * Pre-existing callers are not required to clear a2 before
         * ecall. The privilege bound matches pthread_setschedparam:
         * a thread may not spawn a child above its own base priority.
         *
         * Snapshot td_base_prio once: a cross-hart setschedparam can
         * mutate it between the inherit-default read and the EPERM
         * comparison, and using the same snapshot for both keeps the
         * decision internally consistent.
         */
        u64 a2 = tf->a2;
        if (a2 != 0) {
            if (a2 > (u64) CONFIG_SCHED_NPRIO)
                return -(i64) EINVAL;
            u8 explicit_prio = (u8) (a2 - 1);
            if (explicit_prio > creator_base_prio)
                return -(i64) EPERM;
            prio = explicit_prio;
        }
    }

    /* Validate the entry point is in an executable VMA. The arg is
     * an opaque pointer the user passes through; do not validate it.
     */
    if (!proc_vma_check_access(td->proc, u_entry, 1, VMA_PERM_EXEC))
        return -(i64) EFAULT;

    struct sched_task *new_td = NULL;
    u32 inherited_sigmask =
        __atomic_load_n(&td->td_sig.blocked, __ATOMIC_RELAXED);
    i32 rc = sched_create_user_thread(td->proc, u_entry, u_arg, prio,
                                      inherited_sigmask, &new_td);
    if (rc < 0)
        return (i64) rc;
    return cap_get_token(td->proc, new_td->td_cap_slot, CAP_TYPE_THREAD);
}

static i64 sys_thread_create_h(struct trap_frame *tf, struct sched_task *td)
{
    return sys_thread_create_common(tf, td, false);
}

static i64 sys_thread_create_explicit_h(struct trap_frame *tf,
                                        struct sched_task *td)
{
    return sys_thread_create_common(tf, td, true);
}

static bool thread_target_is_live(const struct sched_task *target)
{
    if (!target)
        return false;
    u8 join_state =
        __atomic_load_n((u8 *) &target->td_join_state, __ATOMIC_ACQUIRE);
    if (join_state == TD_JOIN_EXITED || join_state == TD_JOIN_REAPED)
        return false;
    if (target->state == TD_STATE_TERMINATING)
        return false;
    return true;
}

/* Atomically claim the EXITED -> REAPED transition. Returns true if
 * this caller won the claim (and is now responsible for the final
 * free). All single-byte loads/stores are tear-free; cmpxchg
 * serializes against a concurrent detach or proc_exit racing for the
 * same transition.
 */
static bool thread_claim_reap(struct sched_task *target)
{
    u8 prev = (u8) TD_JOIN_EXITED;
    u8 next = (u8) TD_JOIN_REAPED;
    return __atomic_compare_exchange_n((u8 *) &target->td_join_state, &prev,
                                       next, false, __ATOMIC_ACQ_REL,
                                       __ATOMIC_RELAXED);
}

static bool thread_join_wait_done_locked(struct proc *p, u16 task_slot)
{
    if (!p || task_slot >= PROC_THREAD_MAX)
        return true;
    struct sched_task *target = p->tasks[task_slot];

    return !target || target->td_join_state != TD_JOIN_JOINABLE;
}

static bool thread_join_wait_done(struct proc *p, u16 task_slot)
{
    u64 flags = proc_table_lock_irqsave();
    bool done = thread_join_wait_done_locked(p, task_slot);
    proc_table_unlock_irqrestore(flags);
    return done;
}

static i64 sys_thread_join_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    u64 handle = tf->a0;
    ptr u_exit_code = (ptr) tf->a1;
    struct proc *p = td->proc;

    struct cap_slot_view thread_slot;
    if (!thread_lookup_cap(p, handle, CAP_RIGHT_READ, &thread_slot))
        return -(i64) ESRCH;
    if (thread_slot.slot_index == (u8) td->td_cap_slot)
        return -(i64) EDEADLK;
    u16 task_slot = thread_slot.object_index;

    for (;;) {
        struct sched_task *target = NULL;
        i32 join_state = TD_JOIN_FREE;
        i32 exit_code = 0;

        u64 pflags = proc_table_lock_irqsave();
        target = thread_from_cap_locked(p, &thread_slot);
        if (target) {
            join_state = (i32) __atomic_load_n((u8 *) &target->td_join_state,
                                               __ATOMIC_ACQUIRE);
            if (join_state == TD_JOIN_EXITED) {
                if (u_exit_code &&
                    !user_addr_writable(u_exit_code, sizeof(i32))) {
                    proc_table_unlock_irqrestore(pflags);
                    return -(i64) EFAULT;
                }
                exit_code = target->td_exit_code;
                if (thread_claim_reap(target)) {
                    i64 thread_token =
                        proc_reap_exited_thread_locked(p, target);
                    proc_table_unlock_irqrestore(pflags);
                    if (thread_token >= 0)
                        (void) cap_drop_token(p, (u64) thread_token);
                    wake_up(&p->thread_event_wq, I32_MAX);
                    sched_reap_user_thread(target);
                    if (u_exit_code) {
                        i64 rc = copy_to_user(u_exit_code, &exit_code,
                                              sizeof(exit_code));
                        if (rc < 0)
                            return rc;
                    }
                    return 0;
                }
                join_state = (i32) __atomic_load_n(
                    (u8 *) &target->td_join_state, __ATOMIC_ACQUIRE);
            }
        }
        proc_table_unlock_irqrestore(pflags);

        if (!target)
            return -(i64) ESRCH;
        if (join_state == TD_JOIN_DETACHED || join_state == TD_JOIN_REAPED)
            return -(i64) EINVAL;
        if (join_state == TD_JOIN_EXITED)
            return -(i64) EINVAL;

        /* JOINABLE: block on a process-stable waitqueue, then re-lookup
         * the target under proc_table_lock. The target task itself may be
         * detached and reaped while we sleep, so waiting on td_join_wq
         * would let a concurrent free race this dereference.
         */
        enum wait_unblock_reason reason;
        wait_event_reason(p->thread_event_wq,
                          thread_join_wait_done(p, task_slot), reason);
        if (wait_unblock_is_terminal(reason))
            return -(i64) EINTR;
        /* Loop back: re-take the locks and observe the new state. */
    }
}

static i64 sys_thread_detach_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    u64 handle = tf->a0;
    struct proc *p = td->proc;

    struct cap_slot_view thread_slot;
    if (!thread_lookup_cap(p, handle, CAP_RIGHT_WRITE, &thread_slot))
        return -(i64) ESRCH;

    u64 pflags = proc_table_lock_irqsave();
    struct sched_task *target = thread_from_cap_locked(p, &thread_slot);
    if (!target) {
        proc_table_unlock_irqrestore(pflags);
        return -(i64) ESRCH;
    }
    /* Try the JOINABLE -> DETACHED transition first; if it succeeds
     * the task is alive (or transitioning) and sched_destroy_dead_
     * task will see DETACHED and free without going through EXITED.
     */
    u8 expect = (u8) TD_JOIN_JOINABLE;
    bool claimed_join = __atomic_compare_exchange_n(
        (u8 *) &target->td_join_state, &expect, (u8) TD_JOIN_DETACHED, false,
        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
    bool claimed_reap = false;
    if (!claimed_join)
        claimed_reap = thread_claim_reap(target);
    i64 thread_token = -(i64) EBADF;
    if (claimed_reap)
        thread_token = proc_reap_exited_thread_locked(p, target);
    proc_table_unlock_irqrestore(pflags);

    if (claimed_join) {
        /* Wake any pending joiners so they observe DETACHED and
         * return EINVAL.
         */
        wake_up(&target->td_join_wq, I32_MAX);
        wake_up(&p->thread_event_wq, I32_MAX);
        return 0;
    }
    if (claimed_reap) {
        if (thread_token >= 0)
            (void) cap_drop_token(p, (u64) thread_token);
        /* Target already exited; this caller wins the reap. */
        wake_up(&p->thread_event_wq, I32_MAX);
        sched_reap_user_thread(target);
        return 0;
    }
    /* Already DETACHED or REAPED. */
    return -(i64) EINVAL;
}

static i64 sys_thread_exit_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    i32 code = (i32) tf->a0;
    struct proc *p = td->proc;

    /* Last-thread exit collapses to whole-process exit so a process
     * with only worker threads still releases its proc slot.
     */
    bool last_thread = false;
    u64 pflags = proc_table_lock_irqsave();
    td->td_exit_code = code;
    td->td_exit_started = true;
    u8 live_threads = 0;
    for (u8 i = 0; i < PROC_THREAD_MAX; i++) {
        struct sched_task *other = p->tasks[i];
        if (!other || other == td)
            continue;
        if (!other->td_exit_started)
            live_threads++;
    }
    if (live_threads == 0)
        last_thread = true;
    proc_table_unlock_irqrestore(pflags);

    if (last_thread) {
        proc_exit(p, code);
        sched_set_task_state(td, TD_STATE_TERMINATING);
        return 0;
    }

    futex_exit_robust_list_task(td);
    sched_set_task_state(td, TD_STATE_TERMINATING);
    return 0;
}

static i64 sys_thread_self_h(struct trap_frame *tf __unused,
                             struct sched_task *td)
{
    if (!td)
        return -(i64) EPERM;
    return cap_get_token(td->proc, td->td_cap_slot, CAP_TYPE_THREAD);
}

/* pthread_cancel(tid): mark the target thread cancellation-pending.
 * Cancellation is deferred: the target observes the bit at the next
 * cancellation point (any blocking syscall) and exits with code
 * -ECANCELED. tid==0 is rejected (target self via testcancel).
 */
static i64 sys_thread_cancel_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    u64 handle = tf->a0;
    struct proc *p = td->proc;

    struct cap_slot_view thread_slot;
    if (!thread_lookup_cap(p, handle, CAP_RIGHT_WRITE, &thread_slot))
        return -(i64) ESRCH;

    u64 pflags = proc_table_lock_irqsave();
    struct sched_task *target = thread_from_cap_locked(p, &thread_slot);
    bool target_live = thread_target_is_live(target);
    if (target_live)
        __atomic_store_n(&target->td_cancel_pending, true, __ATOMIC_RELAXED);
    proc_table_unlock_irqrestore(pflags);
    if (!target_live)
        return -(i64) ESRCH;

    /* Nudge a blocked target so it reaches the cancellation point promptly. */
    sched_cancel_blocked(target);
    return 0;
}

/* pthread_setcancelstate(state, oldstate):
 *   state = PTHREAD_CANCEL_ENABLE / DISABLE.
 *   a0 = new state, a1 = user *i32 to receive old state (NULL ok).
 */
static i64 sys_thread_setcancelstate_h(struct trap_frame *tf,
                                       struct sched_task *td)
{
    if (!td)
        return -(i64) EPERM;
    i32 new_state = (i32) tf->a0;
    ptr u_old = (ptr) tf->a1;
    if (new_state != PTHREAD_CANCEL_ENABLE &&
        new_state != PTHREAD_CANCEL_DISABLE)
        return -(i64) EINVAL;

    bool old_disabled = td->td_cancel_disabled;
    if (u_old) {
        i32 old_state =
            old_disabled ? PTHREAD_CANCEL_DISABLE : PTHREAD_CANCEL_ENABLE;
        i64 rc = copy_to_user(u_old, &old_state, sizeof(old_state));
        if (rc < 0)
            return rc;
    }
    td->td_cancel_disabled = (new_state == PTHREAD_CANCEL_DISABLE);
    return 0;
}

/* pthread_testcancel(): if cancellation is pending and not disabled,
 * exit the calling thread with code -ECANCELED. Otherwise return 0.
 * Routes through sys_thread_exit_h so the lifecycle is identical to
 * an explicit pthread_exit, including last-thread collapse to
 * proc_exit.
 */
static i64 sys_thread_testcancel_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td)
        return -(i64) EPERM;
    if (thread_cancel_enabled_pending(td))
        return cancel_thread_now(tf, td);
    return 0;
}

/* pthread_setschedparam / pthread_getschedparam: per-target priority
 * accessors. tid==0 means self, matching the "self" convention used
 * by sched_setaffinity. The caller may not raise a target above its
 * own base priority (privilege bound).
 */
static i64 sys_thread_setschedparam_h(struct trap_frame *tf,
                                      struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    u64 handle = tf->a0;
    i32 new_prio = (i32) tf->a1;

    if (new_prio < SCHED_PRIO_IDLE || new_prio >= CONFIG_SCHED_NPRIO)
        return -(i64) EINVAL;
    if ((u8) new_prio > td->td_base_prio)
        return -(i64) EPERM;

    struct sched_task *target = td;
    if (handle != 0) {
        struct cap_slot_view thread_slot;
        if (!thread_lookup_cap(td->proc, handle, CAP_RIGHT_WRITE, &thread_slot))
            return -(i64) ESRCH;
        if (thread_slot.slot_index == (u8) td->td_cap_slot) {
            td->td_base_prio = (u8) new_prio;
            pi_mutex_refresh_prio(td);
            return 0;
        }
        u64 pflags = proc_table_lock_irqsave();
        target = thread_from_cap_locked(td->proc, &thread_slot);
        if (target) {
            target->td_base_prio = (u8) new_prio;
            pi_mutex_refresh_prio(target);
        }
        proc_table_unlock_irqrestore(pflags);
        if (!target)
            return -(i64) ESRCH;
        return 0;
    }
    target->td_base_prio = (u8) new_prio;
    pi_mutex_refresh_prio(target);
    return 0;
}

static i64 sys_thread_getschedparam_h(struct trap_frame *tf,
                                      struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    u64 handle = tf->a0;
    if (handle == 0)
        return (i64) td->td_base_prio;

    struct cap_slot_view thread_slot;
    if (!thread_lookup_cap(td->proc, handle, CAP_RIGHT_READ, &thread_slot))
        return -(i64) ESRCH;
    if (thread_slot.slot_index == (u8) td->td_cap_slot)
        return (i64) td->td_base_prio;
    u64 pflags = proc_table_lock_irqsave();
    struct sched_task *target = thread_from_cap_locked(td->proc, &thread_slot);
    i64 result = target ? (i64) target->td_base_prio : -(i64) ESRCH;
    proc_table_unlock_irqrestore(pflags);
    return result;
}

/* sched_setscheduler / sched_getscheduler. Mazu has one effective
 * policy (priority-based FIFO with EEVDF tiebreaker); SCHED_OTHER
 * and SCHED_RR are accepted but treated as SCHED_FIFO. The deadline
 * class has its own ABI (SYS_SCHED_SETATTR) and is not selectable
 * here.
 *
 * a0 = pid (0 = self), a1 = policy, a2 = priority. When a1==-1 the
 * call is a get rather than a set; the tristate keeps the syscall
 * count flat and matches glibc's pthread thin wrappers.
 */
static i64 sys_sched_setscheduler_h(struct trap_frame *tf,
                                    struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    i64 raw_pid = (i64) tf->a0;
    i32 policy = (i32) tf->a1;
    i32 prio = (i32) tf->a2;

    if (raw_pid < 0 || raw_pid > (i64) U16_MAX)
        return -(i64) EINVAL;
    if (policy != SCHED_FIFO && policy != SCHED_OTHER && policy != SCHED_RR)
        return -(i64) EINVAL;
    if (prio < SCHED_PRIO_IDLE || prio >= CONFIG_SCHED_NPRIO)
        return -(i64) EINVAL;
    if ((u8) prio > td->td_base_prio)
        return -(i64) EPERM;

    /* Coerce all three policies to the single supported mapping; the
     * policy argument is preserved purely for the matching getter.
     */
    u16 pid = (u16) raw_pid;
    if (pid == 0) {
        td->td_base_prio = (u8) prio;
        pi_mutex_refresh_prio(td);
        return (i64) SCHED_FIFO;
    }
    u64 pflags = proc_table_lock_irqsave();
    struct proc *target_proc = proc_find_locked(pid);
    struct sched_task *target =
        target_proc ? proc_thread_group_leader(target_proc) : NULL;
    if (target) {
        target->td_base_prio = (u8) prio;
        pi_mutex_refresh_prio(target);
    }
    proc_table_unlock_irqrestore(pflags);
    if (!target)
        return -(i64) ESRCH;
    return (i64) SCHED_FIFO;
}

static i64 sys_sched_getscheduler_h(struct trap_frame *tf,
                                    struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    i64 raw_pid = (i64) tf->a0;
    if (raw_pid < 0 || raw_pid > (i64) U16_MAX)
        return -(i64) EINVAL;
    u16 pid = (u16) raw_pid;
    if (pid == 0)
        return (i64) SCHED_FIFO;
    u64 pflags = proc_table_lock_irqsave();
    struct proc *target_proc = proc_find_locked(pid);
    bool found = target_proc && proc_thread_group_leader(target_proc);
    proc_table_unlock_irqrestore(pflags);
    return found ? (i64) SCHED_FIFO : -(i64) ESRCH;
}

/* --- Interval timers (item 15f) --- */

static i64 sys_timer_create_h(struct trap_frame *tf __unused,
                              struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    i32 object_index = posix_timer_alloc(td->proc);
    if (object_index < 0)
        return (i64) object_index;
    i32 handle = cap_open_timer(td->proc, (u16) object_index,
                                CAP_RIGHT_READ | CAP_RIGHT_WRITE, -1, false);
    if (handle < 0) {
        posix_timer_put_idx((u16) object_index);
        return (i64) handle;
    }
    return (i64) handle;
}

static i64 sys_timer_settime_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    i32 handle = (i32) tf->a0;
    u64 value_ms = tf->a1;
    u64 interval_ms = tf->a2;
    /* a3 carries the SIGEV_THREAD_ID target. 0 means process-directed
     * (caller did not opt into SIGEV_THREAD_ID). The kernel rejects
     * non-zero TIDs that do not match a live thread of the owning
     * proc up front so misconfigured timers fail at settime, not at
     * silent expiry.
     */
    u16 target_tid = 0;
    if (tf->a3 != 0) {
        struct cap_slot_view target_slot;
        if (!thread_lookup_cap(td->proc, tf->a3, CAP_RIGHT_READ, &target_slot))
            return -(i64) ESRCH;

        u64 pflags = proc_table_lock_irqsave();
        struct sched_task *target =
            thread_from_cap_locked(td->proc, &target_slot);
        bool live = thread_target_is_live(target);
        if (live)
            target_tid = target->id;
        proc_table_unlock_irqrestore(pflags);
        if (!live)
            return -(i64) ESRCH;
    }
    struct cap_ref ref = cap_lookup_timer(td->proc, handle, CAP_RIGHT_WRITE);
    if (!ref.ptr)
        return -(i64) EINVAL;
    i64 rc = (i64) posix_timer_settime_idx(ref.object_index, value_ms,
                                           interval_ms, target_tid);
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_timer_delete_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    i32 handle = (i32) tf->a0;
    struct cap_slot_view slot = cap_slot_read(td->proc, handle);
    if (!slot.valid || slot.type != CAP_TYPE_TIMER)
        return -(i64) EINVAL;
    return cap_drop_token(td->proc, cap_make_handle(&slot));
}

static i64 sys_timer_gettime_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    struct cap_ref ref =
        cap_lookup_timer(td->proc, (i32) tf->a0, CAP_RIGHT_READ);
    if (!ref.ptr)
        return -(i64) EINVAL;
    i64 rc = posix_timer_gettime_idx(ref.object_index);
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_timer_getoverrun_h(struct trap_frame *tf, struct sched_task *td)
{
    if (!td || !td->proc)
        return -(i64) EPERM;
    struct cap_ref ref =
        cap_lookup_timer(td->proc, (i32) tf->a0, CAP_RIGHT_READ);
    if (!ref.ptr)
        return -(i64) EINVAL;
    i64 rc = posix_timer_getoverrun_idx(ref.object_index);
    cap_put_ref(&ref);
    return rc;
}

static i64 sys_cap_drop_h(struct trap_frame *tf, struct sched_task *td)
{
    return cap_drop_token(td->proc, tf->a0);
}

static i64 sys_cap_transfer_h(struct trap_frame *tf, struct sched_task *td)
{
    i64 raw_pid = (i64) tf->a0;
    if (raw_pid <= 0 || raw_pid > (i64) U16_MAX)
        return -(i64) EINVAL;
    return cap_transfer(td->proc, (u16) raw_pid, tf->a1, (u8) tf->a2);
}

static i64 sys_cap_revoke_delegate_h(struct trap_frame *tf,
                                     struct sched_task *td)
{
    return cap_revoke_delegate(td->proc, tf->a0);
}

static i64 sys_cap_get_token_h(struct trap_frame *tf, struct sched_task *td)
{
    return cap_get_token(td->proc, (i32) tf->a0, (u8) tf->a1);
}

typedef i64 (*syscall_fn_t)(struct trap_frame *tf, struct sched_task *td);

struct syscall_entry {
    syscall_fn_t handler;
    u16 flags;
};

static const struct syscall_entry syscall_table[SYS_NR] = {
    [SYS_OPEN] = {sys_open, SYSCALL_F_NEEDS_PROC},
    [SYS_CLOSE] = {sys_close, SYSCALL_F_NEEDS_PROC},
    [SYS_READ] = {sys_read, SYSCALL_F_NEEDS_PROC},
    [SYS_WRITE] = {sys_write, SYSCALL_F_NEEDS_PROC},
    [SYS_STAT] = {sys_stat, 0},
    [SYS_EXIT] = {sys_exit, 0},
    [SYS_YIELD] = {sys_yield, 0},
    [SYS_TIME] = {sys_time, 0},
    [SYS_SPAWN] = {sys_spawn, SYSCALL_F_NEEDS_PROC},
    [SYS_WAIT] = {sys_wait, SYSCALL_F_NEEDS_PROC},
    [SYS_GETPID] = {sys_getpid, SYSCALL_F_NEEDS_PROC},
    [SYS_GETPPID] = {sys_getppid, SYSCALL_F_NEEDS_PROC},
    [SYS_DUP] = {sys_dup, SYSCALL_F_NEEDS_PROC},
    [SYS_DUP2] = {sys_dup2, SYSCALL_F_NEEDS_PROC},
    [SYS_LSEEK] = {sys_lseek, SYSCALL_F_NEEDS_PROC},
    [SYS_CHDIR] = {sys_chdir, SYSCALL_F_NEEDS_PROC},
    [SYS_GETCWD] = {sys_getcwd, SYSCALL_F_NEEDS_PROC},
    [SYS_FUTEX] = {sys_futex, SYSCALL_F_NEEDS_PROC},
    [SYS_PIPE] = {sys_pipe, SYSCALL_F_NEEDS_PROC},
    [SYS_SYSCONF] = {sys_sysconf, 0},
    [SYS_SCHED_SETAFFINITY] = {sys_sched_setaffinity, 0},
    [SYS_SCHED_GETAFFINITY] = {sys_sched_getaffinity, 0},
#if CONFIG_SCHED_DEADLINE
    [SYS_SCHED_SETATTR] = {sys_sched_setattr, 0},
    [SYS_SCHED_GETATTR] = {sys_sched_getattr, 0},
#endif
    [SYS_SET_ROBUST_LIST] = {sys_set_robust_list, SYSCALL_F_NEEDS_PROC},
    [SYS_GET_ROBUST_LIST] = {sys_get_robust_list, SYSCALL_F_NEEDS_PROC},

    /* PSE51 clock and nanosleep (item 15) */
    [SYS_CLOCK_GETTIME] = {sys_clock_gettime, 0},
    [SYS_CLOCK_GETRES] = {sys_clock_getres, 0},
    [SYS_NANOSLEEP] = {sys_nanosleep, 0},

    /* PSE51 memory locking */
    [SYS_MLOCKALL] = {sys_mlockall, 0},
    [SYS_MUNLOCKALL] = {sys_munlockall, 0},
    [SYS_MLOCK] = {sys_mlock, 0},
    [SYS_MUNLOCK] = {sys_munlock, 0},

    /* PSE51 synchronized I/O */
    [SYS_FSYNC] = {sys_fsync, SYSCALL_F_NEEDS_PROC},
    [SYS_FDATASYNC] = {sys_fdatasync, SYSCALL_F_NEEDS_PROC},

    /* PSE51 single-threaded sigprocmask */
    [SYS_SIGPROCMASK] = {sys_sigprocmask_h, SYSCALL_F_NEEDS_PROC},

    /* PSE51 synchronization (item 15a) */
    [SYS_MUTEX_INIT] = {sys_mutex_init_h, SYSCALL_F_NEEDS_PROC},
    [SYS_MUTEX_LOCK] = {sys_mutex_lock_h, SYSCALL_F_NEEDS_PROC},
    [SYS_MUTEX_TRYLOCK] = {sys_mutex_trylock_h, SYSCALL_F_NEEDS_PROC},
    [SYS_MUTEX_UNLOCK] = {sys_mutex_unlock_h, SYSCALL_F_NEEDS_PROC},
    [SYS_COND_INIT] = {sys_cond_init_h, SYSCALL_F_NEEDS_PROC},
    [SYS_COND_WAIT] = {sys_cond_wait_h, SYSCALL_F_NEEDS_PROC},
    [SYS_COND_TIMEDWAIT] = {sys_cond_timedwait_h, SYSCALL_F_NEEDS_PROC},
    [SYS_COND_SIGNAL] = {sys_cond_signal_h, SYSCALL_F_NEEDS_PROC},
    [SYS_COND_BROADCAST] = {sys_cond_broadcast_h, SYSCALL_F_NEEDS_PROC},
    [SYS_SEM_INIT] = {sys_sem_init_h, SYSCALL_F_NEEDS_PROC},
    [SYS_SEM_WAIT] = {sys_sem_wait_h, SYSCALL_F_NEEDS_PROC},
    [SYS_SEM_TRYWAIT] = {sys_sem_trywait_h, SYSCALL_F_NEEDS_PROC},
    [SYS_SEM_POST] = {sys_sem_post_h, SYSCALL_F_NEEDS_PROC},
    [SYS_SEM_TIMEDWAIT] = {sys_sem_timedwait_h, SYSCALL_F_NEEDS_PROC},

    /* POSIX barriers (item 15i) */
    [SYS_BARRIER_INIT] = {sys_barrier_init_h, SYSCALL_F_NEEDS_PROC},
    [SYS_BARRIER_WAIT] = {sys_barrier_wait_h, SYSCALL_F_NEEDS_PROC},
    [SYS_BARRIER_DESTROY] = {sys_barrier_destroy_h, SYSCALL_F_NEEDS_PROC},

    /* POSIX rwlocks (item 15j) */
    [SYS_RWLOCK_INIT] = {sys_rwlock_init_h, SYSCALL_F_NEEDS_PROC},
    [SYS_RWLOCK_RDLOCK] = {sys_rwlock_rdlock_h, SYSCALL_F_NEEDS_PROC},
    [SYS_RWLOCK_WRLOCK] = {sys_rwlock_wrlock_h, SYSCALL_F_NEEDS_PROC},
    [SYS_RWLOCK_TRYRDLOCK] = {sys_rwlock_tryrdlock_h, SYSCALL_F_NEEDS_PROC},
    [SYS_RWLOCK_TRYWRLOCK] = {sys_rwlock_trywrlock_h, SYSCALL_F_NEEDS_PROC},
    [SYS_RWLOCK_UNLOCK] = {sys_rwlock_unlock_h, SYSCALL_F_NEEDS_PROC},
    [SYS_RWLOCK_TIMEDRDLOCK] = {sys_rwlock_timedrdlock_h, SYSCALL_F_NEEDS_PROC},
    [SYS_RWLOCK_TIMEDWRLOCK] = {sys_rwlock_timedwrlock_h, SYSCALL_F_NEEDS_PROC},
    [SYS_RWLOCK_DESTROY] = {sys_rwlock_destroy_h, SYSCALL_F_NEEDS_PROC},

    /* POSIX message queues (item 15b) */
    [SYS_MQ_OPEN] = {sys_mq_open, SYSCALL_F_NEEDS_PROC},
    [SYS_MQ_CLOSE] = {sys_mq_close, SYSCALL_F_NEEDS_PROC},
    [SYS_MQ_SEND] = {sys_mq_send, SYSCALL_F_NEEDS_PROC},
    [SYS_MQ_RECEIVE] = {sys_mq_receive, SYSCALL_F_NEEDS_PROC},
    [SYS_MQ_TIMEDRECEIVE] = {sys_mq_timedreceive, SYSCALL_F_NEEDS_PROC},

    /* PSE51 scheduling (item 17) */
    [SYS_SCHED_GET_PRIORITY_MIN] = {sys_sched_get_priority_min, 0},
    [SYS_SCHED_GET_PRIORITY_MAX] = {sys_sched_get_priority_max, 0},
    [SYS_SCHED_YIELD] = {sys_sched_yield_pse51, 0},
    [SYS_SCHED_SETPARAM] = {sys_sched_setparam, 0},
    [SYS_SCHED_GETPARAM] = {sys_sched_getparam, 0},

    /* Signals (item 16) */
    [SYS_KILL] = {sys_kill_h, 0},
    [SYS_SIGACTION] = {sys_sigaction_h, SYSCALL_F_NEEDS_PROC},
    [SYS_SIGRETURN] = {sys_sigreturn_h, SYSCALL_F_NEEDS_PROC},

    /* Thread management (item 15d) */
    [SYS_THREAD_CREATE] = {sys_thread_create_h, SYSCALL_F_NEEDS_PROC},
    [SYS_THREAD_CREATE_EXPLICIT] = {sys_thread_create_explicit_h,
                                    SYSCALL_F_NEEDS_PROC},
    [SYS_THREAD_JOIN] = {sys_thread_join_h, SYSCALL_F_NEEDS_PROC},
    [SYS_THREAD_DETACH] = {sys_thread_detach_h, SYSCALL_F_NEEDS_PROC},
    [SYS_THREAD_EXIT] = {sys_thread_exit_h, SYSCALL_F_NEEDS_PROC},
    [SYS_THREAD_SELF] = {sys_thread_self_h, 0},
    [SYS_THREAD_SETSCHEDPARAM] = {sys_thread_setschedparam_h,
                                  SYSCALL_F_NEEDS_PROC},
    [SYS_THREAD_GETSCHEDPARAM] = {sys_thread_getschedparam_h,
                                  SYSCALL_F_NEEDS_PROC},
    [SYS_SCHED_SETSCHEDULER] = {sys_sched_setscheduler_h, SYSCALL_F_NEEDS_PROC},
    [SYS_SCHED_GETSCHEDULER] = {sys_sched_getscheduler_h, SYSCALL_F_NEEDS_PROC},
    [SYS_PTHREAD_KILL] = {sys_pthread_kill_h, SYSCALL_F_NEEDS_PROC},
    [SYS_PTHREAD_SIGMASK] = {sys_pthread_sigmask_h, SYSCALL_F_NEEDS_PROC},
    [SYS_SIGSUSPEND] = {sys_sigsuspend_h, SYSCALL_F_NEEDS_PROC},
    [SYS_SIGTIMEDWAIT] = {sys_sigtimedwait_h, SYSCALL_F_NEEDS_PROC},
    [SYS_SIGQUEUE] = {sys_sigqueue_h, 0},
    [SYS_THREAD_CANCEL] = {sys_thread_cancel_h, SYSCALL_F_NEEDS_PROC},
    [SYS_THREAD_SETCANCELSTATE] = {sys_thread_setcancelstate_h,
                                   SYSCALL_F_NEEDS_PROC},
    [SYS_THREAD_TESTCANCEL] = {sys_thread_testcancel_h, SYSCALL_F_NEEDS_PROC},

    /* Interval timers (item 15f) */
    [SYS_TIMER_CREATE] = {sys_timer_create_h, SYSCALL_F_NEEDS_PROC},
    [SYS_TIMER_SETTIME] = {sys_timer_settime_h, SYSCALL_F_NEEDS_PROC},
    [SYS_TIMER_DELETE] = {sys_timer_delete_h, SYSCALL_F_NEEDS_PROC},
    [SYS_TIMER_GETTIME] = {sys_timer_gettime_h, SYSCALL_F_NEEDS_PROC},
    [SYS_TIMER_GETOVERRUN] = {sys_timer_getoverrun_h, SYSCALL_F_NEEDS_PROC},
    [SYS_CAP_DROP] = {sys_cap_drop_h, SYSCALL_F_NEEDS_PROC},
    [SYS_CAP_TRANSFER] = {sys_cap_transfer_h, SYSCALL_F_NEEDS_PROC},
    [SYS_CAP_REVOKE_DELEGATE] = {sys_cap_revoke_delegate_h,
                                 SYSCALL_F_NEEDS_PROC},
    [SYS_CAP_GET_TOKEN] = {sys_cap_get_token_h, SYSCALL_F_NEEDS_PROC},
};

/* Security counters, global and irq-safe via atomics. */
static u64 sec_nr_denied;
static u64 sec_nr_enosys;

struct syscall_security_stats syscall_security_stats_get(void)
{
    return (struct syscall_security_stats) {
        .nr_denied = __atomic_load_n(&sec_nr_denied, __ATOMIC_RELAXED),
        .nr_enosys = __atomic_load_n(&sec_nr_enosys, __ATOMIC_RELAXED),
    };
}

/* Centralized authorization gate.
 *
 * Checks run before any handler is invoked:
 * 1. Invalid syscall number -> ENOSYS
 * 2. SYSCALL_F_NEEDS_PROC with no process -> EPERM
 * 3. Per-process syscall_allow bitmask (non-zero = whitelist) -> EACCES
 *
 * Denied syscalls are logged to klog and counted for /api/stats.
 */
i64 syscall_dispatch(struct trap_frame *tf, struct sched_task *td)
{
    u64 nr = tf->a7;
    struct proc *proc = td ? td->proc : NULL;
    u16 tid = td ? td->id : 0;

    /* Gate 1: valid syscall number. */
    if (nr >= SYS_NR || !syscall_table[nr].handler) {
        __atomic_add_fetch(&sec_nr_enosys, 1, __ATOMIC_RELAXED);
        klog_security_event("SEC_DENY", proc ? proc->pid : 0, tid, nr, ENOSYS);
        return -(i64) ENOSYS;
    }

    const struct syscall_entry *ent = &syscall_table[nr];

    /* Gate 2: syscalls requiring a process context. */
    if ((ent->flags & SYSCALL_F_NEEDS_PROC) && !proc) {
        __atomic_add_fetch(&sec_nr_denied, 1, __ATOMIC_RELAXED);
        klog_security_event("SEC_DENY", 0, tid, nr, EPERM);
        return -(i64) EPERM;
    }

    /* Gate 3: per-process syscall allow-list (0 = unrestricted).
     * Two u64 words cover syscall numbers 0..127.
     */
    if (proc && (proc->syscall_allow[0] | proc->syscall_allow[1]) != 0) {
        u32 word = (u32) (nr / 64);
        u64 bit = (u64) 1 << (nr % 64);
        if (!(proc->syscall_allow[word] & bit)) {
            __atomic_add_fetch(&sec_nr_denied, 1, __ATOMIC_RELAXED);
            klog_security_event("SEC_DENY", proc->pid, tid, nr, EACCES);
            return -(i64) EACCES;
        }
    }

#ifdef CONFIG_EVENTLOG_SYSCALLS
    u32 _sc_cpu = get_cpuid();
    KTRACE("event=syscall_entry cpu=%hu tid=%hu nr=%lu", _sc_cpu, (u32) tid,
           (u64) nr);
#endif
    i64 ret = ent->handler(tf, td);

#ifdef CONFIG_EVENTLOG_SYSCALLS
    KTRACE("event=syscall_exit cpu=%hu tid=%hu nr=%lu ret=%lu", _sc_cpu,
           (u32) tid, (u64) nr, (u64) ret);
#endif
    return ret;
}

#include __INC_TEST(syscall)
#include __INC_TEST(clock)
#include __INC_TEST(pse51)
