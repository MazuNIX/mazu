/* SPDX-License-Identifier: MIT */
/* posix_spawn-style file actions and spawn attributes.
 *
 * sys_spawn ABI: sys_spawn(path, pathlen, file_actions_ptr, fa_count, attr_ptr)
 * Backward compatible: file_actions_ptr == 0 && attr_ptr == 0 behaves as the
 * original sys_spawn(path, pathlen).
 *
 * The child starts with a spawn-style clone of the parent's inheritable FD
 * table. File actions are then executed sequentially in that child-local
 * table before the child is enqueued. The child is not visible to
 * sys_waitpid or sys_kill until file actions complete and the task is
 * enqueued.
 *
 * Inspired by Spork (posix_spawn emulation for fork-free systems).
 */

#ifndef MAZU_SPAWN_H
#define MAZU_SPAWN_H

#include <mazu/base.h>

/* File action types. */
#define SPAWN_FA_OPEN 0
#define SPAWN_FA_CLOSE 1
#define SPAWN_FA_DUP2 2

/* Maximum number of file actions per spawn call. */
#define SPAWN_FA_MAX 8

/* Maximum path length inside a file action. */
#define SPAWN_FA_PATH_MAX 128

/* Spawn attribute flags. */
#define SPAWN_ATTR_SETPRIO BIT(0) /* apply sched_priority field */

/* A single file action descriptor.  Passed as an array from user-space.
 *
 * Layout for each action type:
 *   SPAWN_FA_OPEN:  fd = target FD, path/pathlen = file to open
 *   SPAWN_FA_CLOSE: fd = FD to close
 *   SPAWN_FA_DUP2:  fd = source FD (oldfd), newfd = target FD
 */
struct spawn_file_action {
    u32 type;    /* SPAWN_FA_OPEN / SPAWN_FA_CLOSE / SPAWN_FA_DUP2 */
    i32 fd;      /* target FD (OPEN/CLOSE) or source FD (DUP2) */
    i32 newfd;   /* target FD for DUP2; unused otherwise */
    u32 pathlen; /* path length for OPEN; unused otherwise */
    u64 path;    /* user pointer to path for OPEN; unused otherwise */
};

/* Spawn attributes descriptor.  Passed as a single struct from user-space. */
struct spawn_attr {
    u32 flags;         /* SPAWN_ATTR_* bitmask */
    u8 sched_priority; /* child scheduling priority (if SPAWN_ATTR_SETPRIO) */
    u8 _pad[3];
};

struct proc;

/* Apply file actions to a child process's capability-backed FD table.
 * Called after binary loading, before the child is enqueued.
 * Returns 0 on success, negative errno on failure.
 */
i32 spawn_apply_file_actions(struct proc *child,
                             const struct spawn_file_action *actions,
                             sz count);

/* Apply spawn attributes to a child process.
 * Returns 0 on success, negative errno on failure.
 */
i32 spawn_apply_attr(struct proc *child,
                     const struct spawn_attr *attr,
                     u8 *out_prio);

#endif /* MAZU_SPAWN_H */
