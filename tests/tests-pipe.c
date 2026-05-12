/* SPDX-License-Identifier: MIT */
#include <kernel/proc/pipe.h>
#include <mazu/selftest.h>

/* Helper: byte-by-byte comparison (no libc memcmp). */
static bool pipe_mem_eq(const void *a, const void *b, sz n)
{
    const u8 *pa = (const u8 *) a;
    const u8 *pb = (const u8 *) b;
    for (sz i = 0; i < n; i++) {
        if (pa[i] != pb[i])
            return false;
    }
    return true;
}

/* Test pipe_alloc creates a valid pipe. */
static i32 selftest_pipe_alloc(void)
{
    struct pipe *p = pipe_alloc();
    assert(p);
    assert(p->readers == 1);
    assert(p->writers == 1);
    assert(pipe_used(p) == 0);

    pipe_close_read(p);
    pipe_close_write(p);
    return 0;
}
DEFINE_SELFTEST(pipe_alloc, selftest_pipe_alloc);

/* Test basic write then read. */
static i32 selftest_pipe_write_read(void)
{
    struct pipe *p = pipe_alloc();
    assert(p);

    const char msg[] = "hello pipe";
    i64 written = pipe_write(p, msg, sizeof(msg));
    assert(written == (i64) sizeof(msg));

    char buf[32];
    i64 got = pipe_read(p, buf, sizeof(buf));
    assert(got == (i64) sizeof(msg));
    assert(pipe_mem_eq(buf, msg, sizeof(msg)));

    pipe_close_read(p);
    pipe_close_write(p);
    return 0;
}
DEFINE_SELFTEST(pipe_write_read, selftest_pipe_write_read);

/* Test pipe EOF: close write end, read returns 0. */
static i32 selftest_pipe_eof(void)
{
    struct pipe *p = pipe_alloc();
    assert(p);

    /* Write some data first. */
    const char msg[] = "data";
    i64 written = pipe_write(p, msg, 4);
    assert(written == 4);

    /* Close write end. */
    pipe_close_write(p);

    /* Read should return the data. */
    char buf[16];
    i64 got = pipe_read(p, buf, sizeof(buf));
    assert(got == 4);
    assert(pipe_mem_eq(buf, msg, 4));

    /* Second read should return 0 (EOF). */
    got = pipe_read(p, buf, sizeof(buf));
    assert(got == 0);

    pipe_close_read(p);
    return 0;
}
DEFINE_SELFTEST(pipe_eof, selftest_pipe_eof);

/* Test pipe EPIPE: close read end, write returns -EPIPE. */
static i32 selftest_pipe_epipe(void)
{
    struct pipe *p = pipe_alloc();
    assert(p);

    pipe_close_read(p);

    const char msg[] = "doomed";
    i64 written = pipe_write(p, msg, 6);
    assert(written == -(i64) EPIPE);

    pipe_close_write(p);
    return 0;
}
DEFINE_SELFTEST(pipe_epipe, selftest_pipe_epipe);

/* Test pipe fills to capacity. */
static i32 selftest_pipe_full(void)
{
    struct pipe *p = pipe_alloc();
    assert(p);

    /* Fill the pipe completely. */
    u8 wbuf[256];
    memset(wbuf, 0xAB, sizeof(wbuf));
    sz total_written = 0;
    while (total_written < PIPE_BUF_SIZE) {
        sz chunk = PIPE_BUF_SIZE - total_written;
        if (chunk > sizeof(wbuf))
            chunk = sizeof(wbuf);
        i64 w = pipe_write(p, wbuf, chunk);
        assert(w > 0);
        total_written += (sz) w;
    }
    assert(total_written == PIPE_BUF_SIZE);

    /* Read it all back. */
    u8 rbuf[256];
    sz total_read = 0;
    while (total_read < PIPE_BUF_SIZE) {
        sz chunk = PIPE_BUF_SIZE - total_read;
        if (chunk > sizeof(rbuf))
            chunk = sizeof(rbuf);
        i64 r = pipe_read(p, rbuf, chunk);
        assert(r > 0);
        for (sz i = 0; i < (sz) r; i++)
            assert(rbuf[i] == 0xAB);
        total_read += (sz) r;
    }
    assert(total_read == PIPE_BUF_SIZE);

    pipe_close_read(p);
    pipe_close_write(p);
    return 0;
}
DEFINE_SELFTEST(pipe_full, selftest_pipe_full);

/* Test multiple writes then multiple reads. */
static i32 selftest_pipe_multi_write(void)
{
    struct pipe *p = pipe_alloc();
    assert(p);

    /* Three writes. */
    i64 w1 = pipe_write(p, "AAA", 3);
    assert(w1 == 3);
    i64 w2 = pipe_write(p, "BB", 2);
    assert(w2 == 2);
    i64 w3 = pipe_write(p, "C", 1);
    assert(w3 == 1);

    /* Single read gets all 6 bytes. */
    char buf[16];
    i64 got = pipe_read(p, buf, sizeof(buf));
    assert(got == 6);
    assert(pipe_mem_eq(buf, "AAABBC", 6));

    pipe_close_read(p);
    pipe_close_write(p);
    return 0;
}
DEFINE_SELFTEST(pipe_multi_write, selftest_pipe_multi_write);

/* Test zero-length read returns immediately. */
static i32 selftest_pipe_zero_len(void)
{
    struct pipe *p = pipe_alloc();
    assert(p);

    char buf[4];
    i64 r = pipe_read(p, buf, 0);
    assert(r == 0); /* zero-length read returns 0 immediately */

    pipe_close_read(p);
    pipe_close_write(p);
    return 0;
}
DEFINE_SELFTEST(pipe_zero_len, selftest_pipe_zero_len);

/* Test FD-level pipe via proc. */
static i32 selftest_pipe_fd_install(void)
{
    struct proc *pr = proc_alloc();
    assert(pr);

    struct pipe *p = pipe_alloc();
    assert(p);

    /* Install read end at FD 3, write end at FD 4. */
    assert(cap_open_pipe(pr, p, true, CAP_RIGHT_READ | CAP_RIGHT_GRANT, 3,
                         true) == 3);
    assert(cap_open_pipe(pr, p, false, CAP_RIGHT_WRITE | CAP_RIGHT_GRANT, 4,
                         true) == 4);

    /* Write via pipe, read via pipe. */
    const char msg[] = "fd-test";
    i64 w = pipe_write(p, msg, 7);
    assert(w == 7);

    char buf[16];
    i64 r = pipe_read(p, buf, sizeof(buf));
    assert(r == 7);
    assert(pipe_mem_eq(buf, msg, 7));

    /* Close both FDs (triggers pipe_close via proc_close_fd). */
    proc_close_fd(pr, 4);
    proc_close_fd(pr, 3);

    proc_free(pr);
    return 0;
}
DEFINE_SELFTEST(pipe_fd_install, selftest_pipe_fd_install);

/* Test wrap-around: write past the buffer boundary and read back. */
static i32 selftest_pipe_wraparound(void)
{
    struct pipe *p = pipe_alloc();
    assert(p);

    /* Fill 3/4 of the buffer, read it all, then write again to wrap. */
    u8 fill[256];
    memset(fill, 0x42, sizeof(fill));

    sz quarter = PIPE_BUF_SIZE / 4;
    for (sz i = 0; i < 3; i++) {
        sz written = 0;
        while (written < quarter) {
            sz chunk = quarter - written;
            if (chunk > sizeof(fill))
                chunk = sizeof(fill);
            i64 w = pipe_write(p, fill, chunk);
            assert(w > 0);
            written += (sz) w;
        }
    }

    /* Read it all to advance head. */
    u8 drain[256];
    sz total_drained = 0;
    while (total_drained < 3 * quarter) {
        i64 r = pipe_read(p, drain, sizeof(drain));
        assert(r > 0);
        total_drained += (sz) r;
    }

    /* Now head is at 3/4.  Write 2 quarters to wrap around. */
    memset(fill, 0x77, sizeof(fill));
    sz written = 0;
    while (written < 2 * quarter) {
        sz chunk = 2 * quarter - written;
        if (chunk > sizeof(fill))
            chunk = sizeof(fill);
        i64 w = pipe_write(p, fill, chunk);
        assert(w > 0);
        written += (sz) w;
    }

    /* Read back the wrapped data. */
    u8 rbuf[256];
    sz total_read = 0;
    while (total_read < 2 * quarter) {
        i64 r = pipe_read(p, rbuf, sizeof(rbuf));
        assert(r > 0);
        for (sz i = 0; i < (sz) r; i++)
            assert(rbuf[i] == 0x77);
        total_read += (sz) r;
    }

    pipe_close_read(p);
    pipe_close_write(p);
    return 0;
}
DEFINE_SELFTEST(pipe_wraparound, selftest_pipe_wraparound);

/* Test dup refcount: closing original write FD doesn't signal EOF
 * if a dup'd copy still exists (i.e., writers refcount is accurate).
 */
static i32 selftest_pipe_dup_refcount(void)
{
    struct pipe *p = pipe_alloc();
    assert(p);
    assert(p->readers == 1);
    assert(p->writers == 1);

    /* Simulate dup of write end: bump writers. */
    u64 flags = spin_lock_irqsave(&p->lock);
    p->writers++;
    spin_unlock_irqrestore(&p->lock, flags);
    assert(p->writers == 2);

    /* Close one writer (the "original"). */
    pipe_close_write(p);
    assert(p->writers == 1);

    /* Pipe should NOT be dead: reader should still be able to receive
     * data from the remaining writer.
     */
    const char msg[] = "dup-ok";
    i64 w = pipe_write(p, msg, 6);
    assert(w == 6);

    char buf[16];
    i64 r = pipe_read(p, buf, sizeof(buf));
    assert(r == 6);
    assert(pipe_mem_eq(buf, msg, 6));

    /* Close remaining writer -> EOF. */
    pipe_close_write(p);

    r = pipe_read(p, buf, sizeof(buf));
    assert(r == 0); /* EOF */

    pipe_close_read(p);
    return 0;
}
DEFINE_SELFTEST(pipe_dup_refcount, selftest_pipe_dup_refcount);
