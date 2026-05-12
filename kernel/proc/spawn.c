/* SPDX-License-Identifier: MIT */
/* posix_spawn file actions and spawn attributes.
 *
 * Executes file actions (open/close/dup2) in the child's FD table before
 * the child is enqueued. The child already holds its inherited parent FD
 * snapshot at this point, so ordered mutations are resolved entirely against
 * the child-local table. All mutations hold the child's fd_lock. The child
 * is in EMBRYO state during this phase - not yet visible to
 * other tasks or harts.
 */

#include <mazu/cap.h>
#include <mazu/proc.h>
#include <mazu/sched.h>
#include <mazu/spawn.h>
#include <mazu/string.h>
#include <mazu/vfs.h>

static i32 fa_open(struct proc *child, i32 fd, char *kpath, sz pathlen)
{
    if (fd < 0 || fd >= PROC_FD_MAX)
        return -(i32) EBADF;

    struct str path = str_new(kpath, pathlen);
    struct result_vfs_stat st = vfs_stat(path);
    if (st.is_error)
        return -(i32) st.code;
    struct vfs_stat vstat = result_vfs_stat_checked(st);
    /* Permit GRANT on supervisor-opened FDs explicitly flagged for delegation.
     * SPAWN_FA_OPEN is exactly that path: the parent is configuring the child's
     * FD table at spawn time, so the minted cap carries GRANT and preserves the
     * normal spawn inheritance semantics. Plain sys_open still mints a
     * non-delegable cap.
     */
    u8 rights = CAP_RIGHT_READ | CAP_RIGHT_GRANT;
    if ((vstat.flags & VFS_FLAG_RDONLY) == 0)
        rights |= CAP_RIGHT_WRITE;
    bool is_seekable = (vstat.flags & VFS_FLAG_NOSEEK) == 0;

    struct result_vfs_file fres = vfs_open(path);
    if (fres.is_error)
        return -(i32) fres.code;
    i32 rc = cap_open_vfs(child, result_vfs_file_checked(fres), rights,
                          is_seekable, fd, true);
    return rc < 0 ? rc : 0;
}

static i32 fa_close(struct proc *child, i32 fd)
{
    if (fd < 0 || fd >= PROC_FD_MAX)
        return -(i32) EBADF;
    /* POSIX posix_spawn_file_actions_addclose ignores already-closed FDs. */
    i64 rc = cap_close_fd(child, fd);
    return rc == -(i64) EBADF ? 0 : (i32) rc;
}

static i32 fa_dup2(struct proc *child, i32 oldfd, i32 newfd)
{
    if (oldfd < 0 || oldfd >= PROC_FD_MAX)
        return -(i32) EBADF;
    if (newfd < 0 || newfd >= PROC_FD_MAX)
        return -(i32) EBADF;

    i32 rc = cap_dup_fd(child, oldfd, newfd, true);
    return rc < 0 ? rc : 0;
}

/* Actions execute in caller order, matching posix_spawn semantics, against
 * the child's already-inherited FD table.
 */
i32 spawn_apply_file_actions(struct proc *child,
                             const struct spawn_file_action *actions,
                             sz count)
{
    if (count == 0)
        return 0;
    if (count > SPAWN_FA_MAX)
        return -(i32) EINVAL;

    /* Validate all entries up front so a malformed action late in the
     * list fails before any side effect lands on the child.
     */
    for (sz i = 0; i < count; i++) {
        const struct spawn_file_action *fa = &actions[i];
        switch (fa->type) {
        case SPAWN_FA_OPEN:
            if (fa->pathlen == 0 || fa->pathlen > SPAWN_FA_PATH_MAX)
                return -(i32) EINVAL;
            break;
        case SPAWN_FA_CLOSE:
        case SPAWN_FA_DUP2:
            break;
        default:
            return -(i32) EINVAL;
        }
    }

    for (sz i = 0; i < count; i++) {
        const struct spawn_file_action *fa = &actions[i];
        i32 rc = 0;
        switch (fa->type) {
        case SPAWN_FA_CLOSE:
            rc = fa_close(child, fa->fd);
            if (rc < 0)
                return rc;
            break;
        case SPAWN_FA_OPEN:
            rc = fa_open(child, fa->fd, (char *) fa->path, fa->pathlen);
            if (rc < 0)
                return rc;
            break;
        case SPAWN_FA_DUP2:
            rc = fa_dup2(child, fa->fd, fa->newfd);
            if (rc < 0)
                return rc;
            break;
        default:
            return -(i32) EINVAL;
        }
    }

    return 0;
}

i32 spawn_apply_attr(struct proc *child __unused,
                     const struct spawn_attr *attr,
                     u8 *out_prio)
{
    if (!attr)
        return 0;

    /* Reject unknown flags. */
    if (attr->flags & ~(u32) SPAWN_ATTR_SETPRIO)
        return -(i32) EINVAL;

    if (attr->flags & SPAWN_ATTR_SETPRIO) {
        if (attr->sched_priority >= CONFIG_SCHED_NPRIO)
            return -(i32) EINVAL;
        *out_prio = attr->sched_priority;
    }

    return 0;
}

#include __INC_TEST(spawn)
