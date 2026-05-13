/* SPDX-License-Identifier: MIT */
/* PSE51 pthread_attr_* surface.
 *
 * Header-only library that synthesizes POSIX pthread attribute objects on top
 * of the Mazu kernel ABI. The kernel exposes the resolved thread tuple directly
 * (entry, arg, priority) via SYS_THREAD_CREATE and SYS_THREAD_CREATE_EXPLICIT;
 * this header gives a userspace caller the POSIX-shaped attribute API to build
 * that tuple.
 *
 * All functions return a positive errno on failure (POSIX convention) and 0 on
 * success. Storage lives entirely inside the caller-provided pthread_attr_t;
 * nothing here performs a syscall and nothing here allocates.
 *
 * The wider pthread synchronization surface has not landed yet. When
 * pthread_{mutex,cond}_* wrappers are added, they should target the futex PI
 * ABI (FUTEX_LOCK_PI, FUTEX_UNLOCK_PI, FUTEX_CMP_REQUEUE_PI) so user space
 * converges on one PI mechanism instead of carrying both futex and
 * kernel-handle mutex paths.
 *
 * Mazu specifics:
 * - Mutex policy is fixed to priority-inheritance with direct handover, so
 *   pthread_attr_setschedpolicy accepts SCHED_OTHER, SCHED_FIFO, and SCHED_RR
 *   (the three POSIX policies Mazu treats as effective FIFO) and rejects other
 *   values with EINVAL.
 * - Stack placement is governed by the shared address-space model: each thread
 *   slot owns a fixed per-process VA band. The kernel therefore exposes exactly
 *   one usable stack size (USER_STACK_SIZE) and cannot honor a caller-supplied
 *   stack region. pthread_attr_setstacksize succeeds only for USER_STACK_SIZE;
 *   pthread_attr_setstack always returns ENOTSUP.
 * - The stack-size accessors use Mazu's signed sz (ptrdiff_t) for consistency
 *   with the rest of the codebase, where POSIX would specify size_t. Negative
 *   values are rejected by the PTHREAD_STACK_MIN bound check; a future libc
 *   shim that exposes the size_t form converts at the boundary.
 */

#ifndef MAZU_PTHREAD_H
#define MAZU_PTHREAD_H

#include <mazu/base.h>
#include <mazu/errordef.h>
#include <mazu/sched.h>
#include <mazu/syscall.h>
#include <mazu/uaccess.h>

/* Detach state. POSIX defaults to JOINABLE. */
#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1

/* Inherit-sched. POSIX defaults to INHERIT_SCHED. */
#define PTHREAD_INHERIT_SCHED 0
#define PTHREAD_EXPLICIT_SCHED 1

/* pshared values. */
#define PTHREAD_PROCESS_PRIVATE 0
#define PTHREAD_PROCESS_SHARED 1

/* Mutex kinds. */
#define PTHREAD_MUTEX_NORMAL 0
#define PTHREAD_MUTEX_RECURSIVE 1
#define PTHREAD_MUTEX_ERRORCHECK 2
#define PTHREAD_MUTEX_DEFAULT 3

/* Mutex protocols. */
#define PTHREAD_PRIO_NONE 0
#define PTHREAD_PRIO_INHERIT 1
#define PTHREAD_PRIO_PROTECT 2

/* Minimum stacksize a portable caller may request. POSIX leaves the
 * exact value implementation-defined; we pick one page so the value is
 * obviously below the kernel's USER_STACK_SIZE (16 KiB).
 */
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 4096
#endif

/* POSIX scheduling parameter object. PSE51 carries only sched_priority. */
struct sched_param {
    i32 sched_priority;
};

/* pthread_attr_t is opaque per POSIX; the fields below are an
 * implementation detail. Callers must use the accessor functions.
 */
typedef struct {
    u8 detachstate;     /* PTHREAD_CREATE_JOINABLE | PTHREAD_CREATE_DETACHED */
    u8 inheritsched;    /* PTHREAD_INHERIT_SCHED | PTHREAD_EXPLICIT_SCHED */
    u8 sched_policy;    /* SCHED_OTHER | SCHED_FIFO | SCHED_RR */
    i32 sched_priority; /* Range checked against the kernel scheduler. */
    void *stackaddr; /* Reserved for getstack roundtrip; always NULL today. */
    sz stacksize;    /* Mirrors the kernel's fixed USER_STACK_SIZE. */
} pthread_attr_t;

typedef struct {
    u8 type;
    u8 protocol;
    u8 pshared;
} pthread_mutexattr_t;

typedef struct {
    u8 pshared;
    i32 clock_id;
} pthread_condattr_t;

typedef struct {
    u8 pshared;
} pthread_rwlockattr_t;

typedef struct {
    u8 pshared;
} pthread_barrierattr_t;

static inline i32 pthread_attr_init(pthread_attr_t *attr)
{
    if (!attr)
        return EINVAL;
    attr->detachstate = PTHREAD_CREATE_JOINABLE;
    attr->inheritsched = PTHREAD_INHERIT_SCHED;
    attr->sched_policy = SCHED_FIFO;
    attr->sched_priority = SCHED_PRIO_NORMAL;
    attr->stackaddr = NULL;
    attr->stacksize = USER_STACK_SIZE;
    return 0;
}

static inline i32 pthread_attr_destroy(pthread_attr_t *attr)
{
    if (!attr)
        return EINVAL;
    /* No owned resources. Stamp every field so use-after-destroy is
     * easier to spot under a debugger or a sanitizer.
     */
    attr->detachstate = 0xFF;
    attr->inheritsched = 0xFF;
    attr->sched_policy = 0xFF;
    attr->sched_priority = -1;
    attr->stackaddr = (void *) (uptr) -1;
    attr->stacksize = -1;
    return 0;
}

static inline i32 pthread_attr_setdetachstate(pthread_attr_t *attr, i32 state)
{
    if (!attr)
        return EINVAL;
    if (state != PTHREAD_CREATE_JOINABLE && state != PTHREAD_CREATE_DETACHED)
        return EINVAL;
    attr->detachstate = (u8) state;
    return 0;
}

static inline i32 pthread_attr_getdetachstate(const pthread_attr_t *attr,
                                              i32 *state)
{
    if (!attr || !state)
        return EINVAL;
    *state = (i32) attr->detachstate;
    return 0;
}

static inline i32 pthread_attr_setinheritsched(pthread_attr_t *attr,
                                               i32 inheritsched)
{
    if (!attr)
        return EINVAL;
    if (inheritsched != PTHREAD_INHERIT_SCHED &&
        inheritsched != PTHREAD_EXPLICIT_SCHED)
        return EINVAL;
    attr->inheritsched = (u8) inheritsched;
    return 0;
}

static inline i32 pthread_attr_getinheritsched(const pthread_attr_t *attr,
                                               i32 *inheritsched)
{
    if (!attr || !inheritsched)
        return EINVAL;
    *inheritsched = (i32) attr->inheritsched;
    return 0;
}

static inline i32 pthread_attr_setschedpolicy(pthread_attr_t *attr, i32 policy)
{
    if (!attr)
        return EINVAL;
    /* Mazu maps SCHED_OTHER and SCHED_RR onto SCHED_FIFO at kernel boundary;
     * the attr roundtrip preserves the caller's stated choice so a portable
     * program sees what it set.
     */
    if (policy != SCHED_OTHER && policy != SCHED_FIFO && policy != SCHED_RR)
        return EINVAL;
    attr->sched_policy = (u8) policy;
    return 0;
}

static inline i32 pthread_attr_getschedpolicy(const pthread_attr_t *attr,
                                              i32 *policy)
{
    if (!attr || !policy)
        return EINVAL;
    *policy = (i32) attr->sched_policy;
    return 0;
}

static inline i32 pthread_attr_setschedparam(pthread_attr_t *attr,
                                             const struct sched_param *param)
{
    if (!attr || !param)
        return EINVAL;
    if (param->sched_priority < SCHED_PRIO_IDLE ||
        param->sched_priority >= CONFIG_SCHED_NPRIO)
        return EINVAL;
    attr->sched_priority = param->sched_priority;
    return 0;
}

static inline i32 pthread_attr_getschedparam(const pthread_attr_t *attr,
                                             struct sched_param *param)
{
    if (!attr || !param)
        return EINVAL;
    param->sched_priority = attr->sched_priority;
    return 0;
}

static inline i32 pthread_attr_setstacksize(pthread_attr_t *attr, sz stacksize)
{
    if (!attr)
        return EINVAL;
    if (stacksize < PTHREAD_STACK_MIN)
        return EINVAL;
    if (stacksize != USER_STACK_SIZE)
        return ENOTSUP;
    attr->stacksize = stacksize;
    return 0;
}

static inline i32 pthread_attr_getstacksize(const pthread_attr_t *attr,
                                            sz *stacksize)
{
    if (!attr || !stacksize)
        return EINVAL;
    *stacksize = attr->stacksize;
    return 0;
}

static inline i32 pthread_attr_setstack(pthread_attr_t *attr,
                                        void *stackaddr,
                                        sz stacksize)
{
    if (!attr)
        return EINVAL;
    (void) stackaddr;
    (void) stacksize;
    /* POSIX semantics require a caller-supplied stack region at stackaddr;
     * Mazu's shared-VA model assigns every thread slot a fixed kernel-chosen
     * stack VA, so the call cannot be honored. Returning ENOTSUP keeps the
     * attr in its previous state and lets a portable caller detect the
     * constraint at runtime.
     */
    return ENOTSUP;
}

static inline i32 pthread_attr_getstack(const pthread_attr_t *attr,
                                        void **stackaddr,
                                        sz *stacksize)
{
    if (!attr || !stackaddr || !stacksize)
        return EINVAL;
    *stackaddr = attr->stackaddr;
    *stacksize = attr->stacksize;
    return 0;
}

/* Resolve attr into the syscall number a future pthread_create wrapper should
 * use: the historical two-argument SYS_THREAD_CREATE when the caller inherits
 * scheduling, or SYS_THREAD_CREATE_EXPLICIT when the wrapper must pass an
 * explicit a2 priority encoding.
 */
static inline u64 pthread_attr_resolve_create_syscall(
    const pthread_attr_t *attr)
{
    if (!attr || attr->inheritsched != PTHREAD_EXPLICIT_SCHED)
        return SYS_THREAD_CREATE;
    return SYS_THREAD_CREATE_EXPLICIT;
}

/* Resolve attr into the explicit-priority value for
 * SYS_THREAD_CREATE_EXPLICIT's a2 register: 0 means inherit, otherwise (prio +
 * 1). The setters validate sched_priority against the kernel range on input, so
 * well-formed attr always produces a value in [1, CONFIG_SCHED_NPRIO]. If a
 * caller manipulates struct directly and parks an out-of-range value, return a
 * sentinel above CONFIG_SCHED_NPRIO so the kernel's own bound check rejects
 * with EINVAL. Silently demoting to inherit would erase the user's stated
 * intent; equally importantly, the (u64) cast of a negative i32 wraps to
 * UINT64_MAX, and the naive "+ 1" would then wrap back to 0 and mimic the
 * inherit encoding, so the bound check below has to run before the cast.
 */
static inline u64 pthread_attr_resolve_prio_arg(const pthread_attr_t *attr)
{
    if (!attr || attr->inheritsched != PTHREAD_EXPLICIT_SCHED)
        return 0;
    if (attr->sched_priority < 0 || attr->sched_priority >= CONFIG_SCHED_NPRIO)
        return (u64) CONFIG_SCHED_NPRIO + 1;
    return (u64) attr->sched_priority + 1;
}

static inline i32 pthread_mutexattr_init(pthread_mutexattr_t *attr)
{
    if (!attr)
        return EINVAL;
    attr->type = PTHREAD_MUTEX_NORMAL;
    attr->protocol = PTHREAD_PRIO_INHERIT;
    attr->pshared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

static inline i32 pthread_mutexattr_destroy(pthread_mutexattr_t *attr)
{
    if (!attr)
        return EINVAL;
    attr->type = 0xFF;
    attr->protocol = 0xFF;
    attr->pshared = 0xFF;
    return 0;
}

static inline i32 pthread_mutexattr_settype(pthread_mutexattr_t *attr, i32 type)
{
    if (!attr)
        return EINVAL;
    if (type != PTHREAD_MUTEX_NORMAL && type != PTHREAD_MUTEX_RECURSIVE &&
        type != PTHREAD_MUTEX_ERRORCHECK && type != PTHREAD_MUTEX_DEFAULT)
        return EINVAL;
    attr->type = (u8) type;
    return 0;
}

static inline i32 pthread_mutexattr_gettype(const pthread_mutexattr_t *attr,
                                            i32 *type)
{
    if (!attr || !type)
        return EINVAL;
    *type = (i32) attr->type;
    return 0;
}

static inline i32 pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr,
                                                i32 protocol)
{
    if (!attr)
        return EINVAL;
    if (protocol == PTHREAD_PRIO_INHERIT) {
        attr->protocol = (u8) protocol;
        return 0;
    }
    if (protocol == PTHREAD_PRIO_NONE || protocol == PTHREAD_PRIO_PROTECT)
        return ENOTSUP;
    return EINVAL;
}

static inline i32 pthread_mutexattr_getprotocol(const pthread_mutexattr_t *attr,
                                                i32 *protocol)
{
    if (!attr || !protocol)
        return EINVAL;
    *protocol = (i32) attr->protocol;
    return 0;
}

static inline i32 pthread_mutexattr_setpshared(pthread_mutexattr_t *attr,
                                               i32 pshared)
{
    if (!attr)
        return EINVAL;
    if (pshared != PTHREAD_PROCESS_PRIVATE && pshared != PTHREAD_PROCESS_SHARED)
        return EINVAL;
    attr->pshared = (u8) pshared;
    return 0;
}

static inline i32 pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr,
                                               i32 *pshared)
{
    if (!attr || !pshared)
        return EINVAL;
    *pshared = (i32) attr->pshared;
    return 0;
}

static inline i32 pthread_condattr_init(pthread_condattr_t *attr)
{
    if (!attr)
        return EINVAL;
    attr->pshared = PTHREAD_PROCESS_PRIVATE;
    attr->clock_id = CLOCK_REALTIME;
    return 0;
}

static inline i32 pthread_condattr_destroy(pthread_condattr_t *attr)
{
    if (!attr)
        return EINVAL;
    attr->pshared = 0xFF;
    attr->clock_id = -1;
    return 0;
}

static inline i32 pthread_condattr_setpshared(pthread_condattr_t *attr,
                                              i32 pshared)
{
    if (!attr)
        return EINVAL;
    if (pshared != PTHREAD_PROCESS_PRIVATE && pshared != PTHREAD_PROCESS_SHARED)
        return EINVAL;
    attr->pshared = (u8) pshared;
    return 0;
}

static inline i32 pthread_condattr_getpshared(const pthread_condattr_t *attr,
                                              i32 *pshared)
{
    if (!attr || !pshared)
        return EINVAL;
    *pshared = (i32) attr->pshared;
    return 0;
}

static inline i32 pthread_condattr_setclock(pthread_condattr_t *attr,
                                            i32 clock_id)
{
    if (!attr)
        return EINVAL;
    if (clock_id != CLOCK_MONOTONIC && clock_id != CLOCK_REALTIME)
        return EINVAL;
    attr->clock_id = clock_id;
    return 0;
}

static inline i32 pthread_condattr_getclock(const pthread_condattr_t *attr,
                                            i32 *clock_id)
{
    if (!attr || !clock_id)
        return EINVAL;
    *clock_id = attr->clock_id;
    return 0;
}

static inline i32 pthread_rwlockattr_init(pthread_rwlockattr_t *attr)
{
    if (!attr)
        return EINVAL;
    attr->pshared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

static inline i32 pthread_rwlockattr_destroy(pthread_rwlockattr_t *attr)
{
    if (!attr)
        return EINVAL;
    attr->pshared = 0xFF;
    return 0;
}

static inline i32 pthread_rwlockattr_setpshared(pthread_rwlockattr_t *attr,
                                                i32 pshared)
{
    if (!attr)
        return EINVAL;
    if (pshared != PTHREAD_PROCESS_PRIVATE && pshared != PTHREAD_PROCESS_SHARED)
        return EINVAL;
    attr->pshared = (u8) pshared;
    return 0;
}

static inline i32 pthread_rwlockattr_getpshared(
    const pthread_rwlockattr_t *attr,
    i32 *pshared)
{
    if (!attr || !pshared)
        return EINVAL;
    *pshared = (i32) attr->pshared;
    return 0;
}

static inline i32 pthread_barrierattr_init(pthread_barrierattr_t *attr)
{
    if (!attr)
        return EINVAL;
    attr->pshared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

static inline i32 pthread_barrierattr_destroy(pthread_barrierattr_t *attr)
{
    if (!attr)
        return EINVAL;
    attr->pshared = 0xFF;
    return 0;
}

static inline i32 pthread_barrierattr_setpshared(pthread_barrierattr_t *attr,
                                                 i32 pshared)
{
    if (!attr)
        return EINVAL;
    if (pshared != PTHREAD_PROCESS_PRIVATE && pshared != PTHREAD_PROCESS_SHARED)
        return EINVAL;
    attr->pshared = (u8) pshared;
    return 0;
}

static inline i32 pthread_barrierattr_getpshared(
    const pthread_barrierattr_t *attr,
    i32 *pshared)
{
    if (!attr || !pshared)
        return EINVAL;
    *pshared = (i32) attr->pshared;
    return 0;
}

#endif /* MAZU_PTHREAD_H */
