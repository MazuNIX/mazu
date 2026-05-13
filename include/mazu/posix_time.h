/* SPDX-License-Identifier: MIT */
/* POSIX time types for PSE51 clock/timer syscalls.
 *
 * Minimal definitions matching the POSIX spec. Only types actually used by Mazu
 * syscalls are defined here.
 */

#ifndef MAZU_POSIX_TIME_H
#define MAZU_POSIX_TIME_H

#include <mazu/base.h>

struct timespec {
    i64 tv_sec;
    i64 tv_nsec;
};

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3

#define TIMER_ABSTIME 1

#define NSEC_PER_SEC 1000000000LL
#define NSEC_PER_MSEC 1000000LL
#define NSEC_PER_USEC 1000LL

/* Internal wait-loop restart code used when CLOCK_REALTIME absolute waits
 * must be re-evaluated after SYS_CLOCK_SETTIME changes the realtime offset.
 * This is a kernel-private sentinel, not part of the userspace errno ABI.
 */
#define MAZU_WAIT_ABORT_CLOCK_SETTIME (-(i32) 4096)

struct sched_task;

void realtime_clock_wait_begin(struct sched_task *td);
void realtime_clock_wait_end(struct sched_task *td);
bool realtime_clock_wait_should_restart(const struct sched_task *td);

#endif /* MAZU_POSIX_TIME_H */
