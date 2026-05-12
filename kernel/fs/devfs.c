/* SPDX-License-Identifier: MIT */
/* Plan 9-style /dev synthetic filesystem.
 *
 * Each device is a static entry with name, read handler, and write handler.
 * The open path is matched against the device table; the device index is
 * stored in vfs_file.private_data (cast to uptr).  No heap allocation.
 */

#include "devfs.h"
#include <mazu/base.h>
#include <mazu/byte.h>
#include <mazu/error.h>
#include <mazu/fmt.h>
#include <mazu/print.h>
#include <mazu/string.h>
#include <mazu/time.h>
#include <mazu/vfs.h>

/* Device handlers */

typedef struct result_sz (*dev_read_fn)(struct byte_buf *buf, sz off);
typedef struct result_sz (*dev_write_fn)(struct byte_view data, sz off);

struct dev_entry {
    struct str name;
    dev_read_fn read;
    dev_write_fn write;
};

/* /dev/null: reads return EOF, writes succeed silently. */
static struct result_sz dev_null_read(struct byte_buf *buf __unused,
                                      sz off __unused)
{
    return result_sz_ok(0);
}

static struct result_sz dev_null_write(struct byte_view data, sz off __unused)
{
    return result_sz_ok(data.len);
}

/* /dev/zero: reads fill with zeros. */
static struct result_sz dev_zero_read(struct byte_buf *buf, sz off __unused)
{
    sz n = byte_buf_append_n(buf, buf->cap - buf->len, 0);
    return result_sz_ok(n);
}

/* /dev/console: writes go to UART via print_str. */
static struct result_sz dev_console_read(struct byte_buf *buf __unused,
                                         sz off __unused)
{
    /* No UART read support yet; return EOF. */
    return result_sz_ok(0);
}

static struct result_sz dev_console_write(struct byte_view data,
                                          sz off __unused)
{
    struct str s = str_new((char *) data.dat, data.len);
    struct result r = print_str(s);
    if (r.is_error)
        return result_sz_error(r.code);
    return result_sz_ok(data.len);
}

/* /dev/time: reads return ASCII nanosecond timestamp.
 * Uses time_current_ms() * 1000000 as an approximation since
 * time_current_ns() is not available.
 */
static struct result_sz dev_time_read(struct byte_buf *buf, sz off)
{
    char tmp[32];
    struct str_buf sb = str_buf_new(tmp, 0, sizeof(tmp));

    u64 ns = time_current_ms().ms * 1000000;
    fmt_append_u64(ns, &sb);
    str_buf_append_char(&sb, '\n');

    return vfs_synth_read(buf, str_from_buf(sb), off);
}

/* /dev/sysname: reads return "mazu\n". */
static struct result_sz dev_sysname_read(struct byte_buf *buf, sz off)
{
    return vfs_synth_read(buf, STR("mazu\n"), off);
}

/* /dev/osversion: reads return the git commit hash. */
static struct result_sz dev_osversion_read(struct byte_buf *buf, sz off)
{
    char tmp[64];
    struct str_buf sb = str_buf_new(tmp, 0, sizeof(tmp));

    str_buf_append(&sb, STR(GIT_COMMIT));
    str_buf_append_char(&sb, '\n');

    return vfs_synth_read(buf, str_from_buf(sb), off);
}

/* Device table */

static struct dev_entry dev_table[] = {
    {STR_STATIC("null"), dev_null_read, dev_null_write},
    {STR_STATIC("zero"), dev_zero_read, NULL},
    {STR_STATIC("console"), dev_console_read, dev_console_write},
    {STR_STATIC("time"), dev_time_read, NULL},
    {STR_STATIC("sysname"), dev_sysname_read, NULL},
    {STR_STATIC("osversion"), dev_osversion_read, NULL},
};

#define DEV_TABLE_SIZE (countof(dev_table))

static struct str dev_name_at(const void *entries, sz idx)
{
    return ((const struct dev_entry *) entries)[idx].name;
}

/* VFS operations
 *
 * Files map to an index in dev_table. The root directory is represented by
 * DEV_TABLE_SIZE.
 */

static struct result_vfs_file devfs_open(void *ctx __unused, struct str path)
{
    return vfs_flat_named_open(path, DEV_TABLE_SIZE, dev_table, DEV_TABLE_SIZE,
                               dev_name_at);
}

static struct result_sz devfs_read(void *ctx __unused,
                                   struct vfs_file *f,
                                   struct byte_buf *buf,
                                   sz off)
{
    sz idx = (sz) (uptr) f->private_data;
    if (idx == (sz) DEV_TABLE_SIZE)
        return result_sz_error(EISDIR); /* directory has no read */
    if (idx < 0 || idx >= (sz) DEV_TABLE_SIZE)
        return result_sz_error(EBADF);

    if (!dev_table[idx].read)
        return result_sz_error(ENOSYS);

    return dev_table[idx].read(buf, off);
}

static struct result_sz devfs_write(void *ctx __unused,
                                    struct vfs_file *f,
                                    struct byte_view data,
                                    sz off)
{
    sz idx = (sz) (uptr) f->private_data;
    if (idx == (sz) DEV_TABLE_SIZE)
        return result_sz_error(EISDIR);
    if (idx < 0 || idx >= (sz) DEV_TABLE_SIZE)
        return result_sz_error(EBADF);

    if (!dev_table[idx].write)
        return result_sz_error(EROFS);

    return dev_table[idx].write(data, off);
}

static struct result_vfs_stat devfs_stat(void *ctx __unused, struct str path)
{
    /* Root directory. */
    if (vfs_path_is_root(path))
        return result_vfs_stat_ok(vfs_rdonly_dir_stat());

    sz idx =
        vfs_named_table_lookup(path, dev_table, DEV_TABLE_SIZE, dev_name_at);
    if (idx < 0)
        return result_vfs_stat_error(ENOENT);

    struct vfs_stat st = vfs_rdonly_file_stat();
    if (dev_table[idx].write != NULL)
        st.flags &= ~(u8) VFS_FLAG_RDONLY;
    return result_vfs_stat_ok(st);
}

static struct result_vfs_dirent devfs_readdir(void *ctx __unused,
                                              struct str dirpath __unused,
                                              sz index)
{
    return vfs_flat_named_readdir(dev_table, DEV_TABLE_SIZE, index,
                                  dev_name_at);
}

struct vfs_ops devfs_vfs_ops(void)
{
    return (struct vfs_ops) {
        .open = devfs_open,
        .close = vfs_noop_close,
        .read = devfs_read,
        .write = devfs_write,
        .stat = devfs_stat,
        .readdir = devfs_readdir,
        .create = vfs_readonly_mutation,
        .unlink = vfs_readonly_mutation,
        .mkdir = vfs_readonly_mutation,
        .rmdir = vfs_readonly_mutation,
    };
}

/* Self-tests */

#include __INC_TEST(devfs)
