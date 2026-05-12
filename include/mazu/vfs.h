/* SPDX-License-Identifier: MIT */
/* Virtual filesystem layer.
 *
 * Routes file operations through a mount table using longest-prefix
 * matching.  Each mount point carries a vfs_ops vtable that dispatches
 * to a concrete filesystem (ramfs, sfs, ...).
 */

#ifndef MAZU_VFS_H
#define MAZU_VFS_H

#include <mazu/base.h>
#include <mazu/byte.h>
#include <mazu/error.h>
#include <mazu/string.h>

#define VFS_TYPE_FILE 0
#define VFS_TYPE_DIR 1
#define VFS_FLAG_RDONLY BIT(0)
/* Backend nodes whose read/write semantics are stream-like rather than
 * positional. Set on synthetic /dev, /proc, /net entries and on real
 * directories. lseek on a NOSEEK descriptor returns ESPIPE.
 */
#define VFS_FLAG_NOSEEK BIT(1)
#define VFS_MAX_MOUNTS 8

struct vfs_stat {
    sz size;
    u8 type;  /* VFS_TYPE_FILE or VFS_TYPE_DIR */
    u8 flags; /* VFS_FLAG_RDONLY */
    u32 etag;
};

struct vfs_dirent {
    struct str name;
    u8 type;
};

struct_result(vfs_stat, struct vfs_stat);
struct_result(vfs_dirent, struct vfs_dirent);

struct vfs_file {
    void *private_data; /* backend-specific (ram_fs_node *, sfs_file *, ...) */
    u8 mount_idx;       /* index into mount table */
};

struct_result(vfs_file, struct vfs_file);

struct vfs_ops {
    struct result_vfs_file (*open)(void *ctx, struct str path);
    void (*close)(void *ctx, struct vfs_file *f);
    struct result_sz (*read)(void *ctx,
                             struct vfs_file *f,
                             struct byte_buf *buf,
                             sz off);
    struct result_sz (*write)(void *ctx,
                              struct vfs_file *f,
                              struct byte_view data,
                              sz off);
    struct result_vfs_stat (*stat)(void *ctx, struct str path);
    struct result_vfs_dirent (*readdir)(void *ctx,
                                        struct str dirpath,
                                        sz index);
    struct result (*create)(void *ctx, struct str path);
    struct result (*unlink)(void *ctx, struct str path);
    struct result (*mkdir)(void *ctx, struct str path);
    struct result (*rmdir)(void *ctx, struct str path);
};

struct vfs_mount {
    char prefix[64];
    sz prefix_len;
    struct vfs_ops ops;
    void *ctx;
    bool active;
};

struct result vfs_mount(struct str path, struct vfs_ops ops, void *ctx);
struct result vfs_unmount(struct str path);
struct result_vfs_file vfs_open(struct str path);
void vfs_close(struct vfs_file *f);
struct result_sz vfs_read(struct vfs_file *f, struct byte_buf *buf, sz off);
struct result_sz vfs_write(struct vfs_file *f, struct byte_view data, sz off);
struct result_vfs_stat vfs_stat(struct str path);
struct result_vfs_dirent vfs_readdir(struct str path, sz index);
struct result vfs_create(struct str path);
struct result vfs_unlink(struct str path);
struct result vfs_mkdir(struct str path);
struct result vfs_rmdir(struct str path);

typedef struct str (*vfs_name_at_fn)(const void *entries, sz idx);

/* Emit buffered content at offset into a read buffer.
 * Shared by synthetic filesystem read handlers (devfs, netfs, procfs).
 */
static inline struct result_sz vfs_synth_read(struct byte_buf *buf,
                                              struct str content,
                                              sz off)
{
    if (!content.dat || off >= content.len)
        return result_sz_ok(0);
    sz avail = content.len - off;
    return result_sz_ok(
        byte_buf_append(buf, byte_view_new(content.dat + off, avail)));
}

static inline bool vfs_path_is_root(struct str path)
{
    return path.len == 0 || (path.len == 1 && path.dat[0] == '/');
}

static inline struct str vfs_path_trim_leading_slash(struct str path)
{
    if (path.len > 0 && path.dat[0] == '/')
        return str_new(path.dat + 1, path.len - 1);
    return path;
}

static inline struct vfs_file vfs_file_id(sz id)
{
    return (struct vfs_file) {
        .private_data = (void *) (uptr) id,
        .mount_idx = 0,
    };
}

static inline struct vfs_stat vfs_rdonly_dir_stat(void)
{
    return (struct vfs_stat) {
        .size = 0,
        .type = VFS_TYPE_DIR,
        .flags = VFS_FLAG_RDONLY | VFS_FLAG_NOSEEK,
        .etag = 0,
    };
}

static inline struct vfs_stat vfs_rdonly_file_stat(void)
{
    return (struct vfs_stat) {
        .size = 0,
        .type = VFS_TYPE_FILE,
        .flags = VFS_FLAG_RDONLY | VFS_FLAG_NOSEEK,
        .etag = 0,
    };
}

static inline struct result vfs_readonly_mutation(void *ctx __unused,
                                                  struct str path __unused)
{
    return result_error(EROFS);
}

static inline void vfs_noop_close(void *ctx __unused,
                                  struct vfs_file *f __unused)
{
}

static inline struct result_sz vfs_readonly_write(void *ctx __unused,
                                                  struct vfs_file *f __unused,
                                                  struct byte_view data
                                                      __unused,
                                                  sz off __unused)
{
    return result_sz_error(EROFS);
}

static inline sz vfs_named_table_lookup(struct str path,
                                        const void *entries,
                                        sz count,
                                        vfs_name_at_fn name_at)
{
    struct str name = vfs_path_trim_leading_slash(path);

    for (sz i = 0; i < count; i++) {
        if (str_is_equal(name, name_at(entries, i)))
            return i;
    }
    return -1;
}

static inline struct result_vfs_file vfs_flat_named_open(struct str path,
                                                         sz dir_id,
                                                         const void *entries,
                                                         sz count,
                                                         vfs_name_at_fn name_at)
{
    if (vfs_path_is_root(path))
        return result_vfs_file_ok(vfs_file_id(dir_id));

    sz idx = vfs_named_table_lookup(path, entries, count, name_at);
    if (idx < 0)
        return result_vfs_file_error(ENOENT);

    return result_vfs_file_ok(vfs_file_id(idx));
}

static inline struct result_vfs_dirent vfs_flat_named_readdir(
    const void *entries,
    sz count,
    sz index,
    vfs_name_at_fn name_at)
{
    if (index < 0 || index >= count)
        return result_vfs_dirent_error(ENOENT);

    return result_vfs_dirent_ok((struct vfs_dirent) {
        .name = name_at(entries, index),
        .type = VFS_TYPE_FILE,
    });
}

/* Return VFS ops for a ramfs backend. */
struct vfs_ops ramfs_vfs_ops(void);

/* Forward declaration. */
struct ram_fs;

/* Initialize VFS and mount the given ramfs at "/". */
void vfs_init(struct ram_fs *rfs);

#endif /* MAZU_VFS_H */
