/* SPDX-License-Identifier: MIT */
/* This file defines a basic error type without a value in it. See error.h for
 * the version that can contain a value on success. The reason for the split is
 * that assert is used by the result with values, but the implementation of
 * assert uses 'struct result' and to avoid a recursive dependency.
 */

#ifndef MAZU_ERRORDEF_H
#define MAZU_ERRORDEF_H

#include <mazu/base.h>
#include <mazu/stringdef.h>

/* Many languages now feature results and options as ways of returning a value
 * that indicates either a success and a valid return value, or an error along
 * with an error code. Implementing this properly requires sum types, which C
 * doesn't support. C also doesn't have type-level polymorphism, so it is not
 * possible to create structures that are generic over the type of some field
 * (e.g. the types of the success and error values could be generics).
 *
 * Two patterns are commonly used in C programs:
 * 1. The 'int' return value that's negative on error and contains, e.g., an
 *    'errno'.
 * 2. An error pointer that also contains either an error or a pointer
 *
 * The downsides of each of these is that at the type-level, it's not visible
 * that some values are potential errors while other aren't. It is also easy
 * to ignore possible error values or forget checks. Additionally, just from
 * looking at the function interface, there is no way to know what values are
 * errors and what values are valid.
 *
 * The 'struct result' type aims to be a middle-ground. It contains fields
 * indicating if there has been an error, an error code, and, possibly, a value
 * that's returned on success. To make the structure generic over the type of
 * the return value, a macro is provided that defines the struct along with
 * its default functions for any type.
 *
 * This is likely less performant than using the aforementioned methods of
 * error handling. However, it's conceivable to optimize some common cases like
 * pointers with niching. Regardless, clarity and safety should come first, and
 * once both are established and code has been written, the performance of this
 * code can be measured and the implementation of the result type can be
 * optimized.
 */

/* Base result type: success or error, no payload. */
struct result {
    bool is_error;
    u16 code;
};

static_assert(sizeof(struct result) == 4, "unexpected result size");

static inline struct result result_error(u16 code)
{
    return (struct result) {
        .is_error = true,
        .code = code,
    };
}

static inline struct result result_ok(void)
{
    return (struct result) {
        .is_error = false,
        .code = 0,
    };
}

/* Error codes.
 * These are the errno values because these are well-known and seem exhaustive
 * enough. For example, see https://en.wikipedia.org/wiki/Errno.h
 */

#define EPERM 1
#define ENOENT 2
#define ESRCH 3
#define EINTR 4
#define EIO 5
#define ENXIO 6
#define ENOEXEC 8
#define EBADF 9
#define ECHILD 10
#define EAGAIN 11
#define ENOMEM 12
#define EACCES 13
#define EFAULT 14
#define EBUSY 16
#define EEXIST 17
#define ENODEV 19
#define ENOTDIR 20
#define EISDIR 21
#define EINVAL 22
#define ENFILE 23
#define EMFILE 24
#define ENOTTY 25
#define EFBIG 27
#define ENOSPC 28
#define ESPIPE 29
#define EROFS 30
#define EPIPE 32
#define ERANGE 34
#define EDEADLK 35
#define ENAMETOOLONG 36
#define ENOSYS 38
#define ENOTEMPTY 39
#define EMSGSIZE 90
#define EADDRINUSE 98
#define EADDRNOTAVAIL 99
#define ECONNRESET 104
#define ENOBUFS 105
#define ETIMEDOUT 110
#define ECONNREFUSED 111
#define EHOSTUNREACH 113
#define ECANCELED 125 /* operation canceled (POSIX, pthread_cancel) */
#define ENOTSUP 95    /* operation not supported (POSIX) */
/* POSIX robust-mutex semantics: the previous owner died holding the lock
 * (EOWNERDEAD), or the protected state cannot be recovered and the mutex
 * is now permanently unusable (ENOTRECOVERABLE).  Numbers match Linux's
 * asm-generic/errno.h so libc wrappers do not need translation.
 */
#define EOWNERDEAD 130
#define ENOTRECOVERABLE 131

static inline struct str error_code_str(u16 code)
{
    switch (code) {
    case EPERM:
        return STR("Operation not permitted (EPERM)");
    case ENOENT:
        return STR("No such file or directory (ENOENT)");
    case ESRCH:
        return STR("No such process (ESRCH)");
    case EINTR:
        return STR("Interrupted system call (EINTR)");
    case EIO:
        return STR("Input/output error (EIO)");
    case ENXIO:
        return STR("No such device or address (ENXIO)");
    case ENOEXEC:
        return STR("Exec format error (ENOEXEC)");
    case EBADF:
        return STR("Bad file descriptor (EBADF)");
    case ECHILD:
        return STR("No child processes (ECHILD)");
    case EAGAIN:
        return STR("Resource temporarily unavailable (EAGAIN)");
    case ENOMEM:
        return STR("Cannot allocate memory (ENOMEM)");
    case EACCES:
        return STR("Permission denied (EACCES)");
    case EFAULT:
        return STR("Bad address (EFAULT)");
    case EBUSY:
        return STR("Device or resource busy (EBUSY)");
    case EEXIST:
        return STR("File exists (EEXIST)");
    case ENODEV:
        return STR("No such device (ENODEV)");
    case ENOTDIR:
        return STR("Not a directory (ENOTDIR)");
    case EISDIR:
        return STR("Is a directory (EISDIR)");
    case EINVAL:
        return STR("Invalid argument (EINVAL)");
    case ENFILE:
        return STR("Too many open files in system (ENFILE)");
    case EMFILE:
        return STR("Too many open files (EMFILE)");
    case ENOTTY:
        return STR("Inappropriate ioctl for device (ENOTTY)");
    case EFBIG:
        return STR("File too large (EFBIG)");
    case ENOSPC:
        return STR("No space left on device (ENOSPC)");
    case ESPIPE:
        return STR("Illegal seek (ESPIPE)");
    case EROFS:
        return STR("Read-only file system (EROFS)");
    case EPIPE:
        return STR("Broken pipe (EPIPE)");
    case ERANGE:
        return STR("Numerical result out of range (ERANGE)");
    case EDEADLK:
        return STR("Resource deadlock avoided (EDEADLK)");
    case ENAMETOOLONG:
        return STR("File name too long (ENAMETOOLONG)");
    case ENOSYS:
        return STR("Function not implemented (ENOSYS)");
    case ENOTEMPTY:
        return STR("Directory not empty (ENOTEMPTY)");
    case EMSGSIZE:
        return STR("Message too long (EMSGSIZE)");
    case EADDRINUSE:
        return STR("Address already in use (EADDRINUSE)");
    case EADDRNOTAVAIL:
        return STR("Address not available (EADDRNOTAVAIL)");
    case ECONNRESET:
        return STR("Connection reset by peer (ECONNRESET)");
    case ENOBUFS:
        return STR("No buffer space available (ENOBUFS)");
    case ETIMEDOUT:
        return STR("Connection timed out (ETIMEDOUT)");
    case ECONNREFUSED:
        return STR("Connection refused (ECONNREFUSED)");
    case EHOSTUNREACH:
        return STR("No route to host (EHOSTUNREACH)");
    case ECANCELED:
        return STR("Operation canceled (ECANCELED)");
    case ENOTSUP:
        return STR("Operation not supported (ENOTSUP)");
    case EOWNERDEAD:
        return STR("Owner died (EOWNERDEAD)");
    case ENOTRECOVERABLE:
        return STR("State not recoverable (ENOTRECOVERABLE)");
    default:
        return STR("Unknown error");
    }
}

#endif /* MAZU_ERRORDEF_H */
