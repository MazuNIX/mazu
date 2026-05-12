/* SPDX-License-Identifier: MIT */
#include <mazu/arena.h>
#include <mazu/base.h>
#include <mazu/error.h>
#include <mazu/ramfs.h>
#include <mazu/vfs.h>

/* Paths */

#define PATH_NAME_MAX_LEN 0x1000

struct path_name {
    /* 'src' holds a copy of the original path name with minimal modifications.
     * The 'components' array contains string slices pointing into 'src'. Each
     * of these slices represents one component of a path without '/'
     * characters.
     */
    struct str src;
    /* The path '/' is represented by a 'struct path_name' where 'n_components'
     * is 0, the empty path.
     */
    sz n_components;
    struct str *components;
    bool is_absolute;
};

struct_result(path_name, struct path_name);

/* Parse a path name into a 'struct path_name'. Uses 'arn' to allocate memory
 * for the fields in the returned 'struct path_name'. Returns an error if the
 * path is invalid or too long. The empty path ('n_components == 0') represents
 * the path '/'.
 */
static struct result_path_name path_name_parse(struct str name,
                                               struct arena *arn)
{
    if (name.dat == NULL || name.len == 0)
        return result_path_name_error(EINVAL);

    if (name.len > PATH_NAME_MAX_LEN)
        return result_path_name_error(ENAMETOOLONG);

    /* All paths must be absolute. */
    if (name.dat[0] != '/')
        return result_path_name_error(EINVAL);
    name.dat++;
    name.len--;

    /* The trailing '/' can be ignored as it has no effect. */
    if (name.len > 0 && name.dat[name.len - 1] == '/')
        name.len--;

    /* Reject embedded NUL bytes. */
    if (!str_find_char(name, '\0').is_none)
        return result_path_name_error(EINVAL);

    struct path_name path;
    path.is_absolute = true;

    /* 'struct path_name' needs to maintain a copy of the name string so that
     * the string slices in 'components' can point to it.
     */
    struct str_buf src_buf = str_buf_from_arena(arn, name.len);
    str_buf_append(&src_buf, name);
    path.src = str_from_buf(src_buf);

    /* A path of length N can at most have C = N / 2 + 1 components.
     *
     * A path with two components (C = 2) of minimum length one contains at
     * least one '/' character, so N = 3 and C = N/2 + 1 = 2 gives the
     * correct count. Adding one minimum-length component requires one more
     * '/', so N' = N + 2 and
     *
     *   C' = N'/2 + 1 = (N + 2)/2 + 1 = N/2 + 1 + 1 = C + 1
     *
     * which is correct.
     */
    sz max_n_components = name.len / 2 + 1;
    path.components = arena_alloc_aligned_array(arn, max_n_components,
                                                sizeof(*path.components),
                                                alignof(*path.components));
    path.n_components = 0;

    struct option_sz opt_idx;
    struct str curr;
    struct str src = path.src;

    while (src.len) {
        /* There can't be any more components than 'max_n_components' (see
         * above).
         */
        assert(path.n_components < max_n_components);

        opt_idx = str_find_char(src, '/');

        if (opt_idx.is_none) {
            curr = str_new(src.dat, src.len);
            src.len = 0;
        } else {
            sz next_len = option_sz_checked(opt_idx);

            if (next_len == 0) {
                /* Another '/' character follows the previous one. Ignore it and
                 * continue.
                 */
                src.len--;
                src.dat++;
                continue;
            }

            curr = str_new(src.dat, next_len);
            /* Add 1 to skip the '/' character. */
            src.len -= next_len + 1;
            src.dat += next_len + 1;
        }

        path.components[path.n_components++] = curr;
    }

    return result_path_name_ok(path);
}

static struct str path_name_to_str(struct path_name path_name,
                                   struct arena *arn)
{
    struct str_buf sbuf = str_buf_from_arena(arn, PATH_NAME_MAX_LEN);
    if (path_name.is_absolute)
        str_buf_append_char(&sbuf, '/');
    for (sz i = 0; i < path_name.n_components; i++) {
        if (i)
            str_buf_append_char(&sbuf, '/');
        str_buf_append(&sbuf, path_name.components[i]);
    }
    return str_from_buf(sbuf);
}

/* Node lookup

 * Lookup the node for 'path' starting at 'curr'. 'path' must be non-empty.
 * Returns 'NULL' if no suitable node was found or 'curr' is 'NULL'.
 */
static struct ram_fs_node *ram_fs_node_lookup_at(struct ram_fs_node *curr,
                                                 struct path_name path)
{
    assert(path.n_components != 0);

    sz i = 0;

    while (curr) {
        if (str_is_equal(curr->name, path.components[i])) {
            if (i + 1 == path.n_components)
                return curr;

            switch (curr->type) {
            case RAM_FS_TYPE_DIR:
                curr = curr->first;
                i++;
                break;
            case RAM_FS_TYPE_FILE:
                /* A file was reached without reaching the end of the path so
                 * the path doesn't exist.
                 */
                return NULL;
            }
        } else {
            /* Go to the next entry in the current directory */
            curr = curr->next;
        }
    }

    return NULL;
}

/* Lookup the node for 'path' starting at the node 'root'. */
static struct ram_fs_node *ram_fs_node_lookup(struct ram_fs_node *root,
                                              struct path_name path)
{
    assert(root);

    if (path.is_absolute) {
        /* Special case for the root directory */
        if (path.n_components == 0)
            return root;

        return ram_fs_node_lookup_at(root->first, path);
    } else {
        /* Relative paths are rejected during parsing, so this fallback should
         * remain unreachable.
         */
        return NULL;
    }
}

/* Node creation */

static struct ram_fs_node *ram_fs_node_alloc(struct ram_fs *rfs,
                                             struct str name,
                                             enum ram_fs_node_type type)
{
    struct ram_fs_node *node = pool_alloc(&rfs->node_alloc);
    if (!node) {
        pr_debug(STR("ramfs: Failed to allocate node for '%.*s'\n"),
                 (int) name.len, name.dat);
        return NULL;
    }
    node->first = NULL;
    node->next = NULL;
    node->type = type;
    node->flags = 0;
    node->fs = rfs;

    char *name_dat = alloc_alloc(rfs->data_alloc, name.len, alignof(void *));
    if (!name_dat) {
        pr_debug(STR("ramfs: Failed to allocate name buffer (len=%ld) for "
                     "'%.*s'\n"),
                 name.len, (int) name.len, name.dat);
        pool_free(&rfs->node_alloc, node);
        return NULL;
    }
    struct str_buf name_buf = str_buf_new(name_dat, 0, name.len);
    str_buf_append(&name_buf, name);
    node->name = str_from_buf(name_buf);
    node->data = byte_buf_new(NULL, 0, 0);
    return node;
}

static struct result_ram_fs_node ram_fs_create_common(
    struct ram_fs_node *root,
    struct str nodepath,
    enum ram_fs_node_type type,
    bool recursive,
    struct arena scratch)
{
    /* Recursive directory creation reuses the caller's scratch arena, so the
     * recursive path must not reset it.
     */

    struct result_path_name path_res = path_name_parse(nodepath, &scratch);
    if (path_res.is_error)
        return result_ram_fs_node_error(path_res.code);

    struct path_name path = result_path_name_checked(path_res);
    if (path.n_components == 0) {
        /* Path was '/'. The root is created along with the file system and must
         * already exist.
         */
        return result_ram_fs_node_error(EEXIST);
    }

    assert(path.is_absolute);
    /* path_name_parse() rejects relative paths, so path.is_absolute is an
     * invariant here.
     * Safe: n_components > 0 was checked above (path is not root).
     */
    struct str nodename = path.components[path.n_components - 1];

    /* For parent lookup, ignore the name of the new node. */
    path.n_components--;
    struct ram_fs_node *parent = ram_fs_node_lookup(root, path);

    if (!parent) {
        if (!recursive) {
            /* Parent directory doesn't exist so this node can't be created. */
            return result_ram_fs_node_error(ENOENT);
        }

        struct str parent_path = path_name_to_str(path, &scratch);
        struct result_ram_fs_node parent_res = ram_fs_create_common(
            root, parent_path, RAM_FS_TYPE_DIR, true, scratch);
        if (parent_res.is_error)
            return parent_res;
        parent = result_ram_fs_node_checked(parent_res);
    }

    if (parent->type != RAM_FS_TYPE_DIR) {
        /* A node cannot be added to a file. */
        return result_ram_fs_node_error(ENOTDIR);
    }

    /* Read-only parent directories cannot be modified. */
    if (parent->flags & RAM_FS_FLAG_READONLY)
        return result_ram_fs_node_error(EROFS);

    /* Look for conflicts */
    if (parent->first) {
        struct ram_fs_node *curr = parent->first;
        while (curr) {
            if (str_is_equal(curr->name, nodename)) {
                return result_ram_fs_node_error(EEXIST);
            }
            curr = curr->next;
        }
    }

    struct ram_fs_node *node = ram_fs_node_alloc(root->fs, nodename, type);
    if (!node)
        return result_ram_fs_node_error(ENOMEM);

    if (parent->first) {
        /* Append the new node to the list of nodes in the parent directory. */
        struct ram_fs_node *curr = parent->first;
        while (curr->next)
            curr = curr->next;
        curr->next = node;
    } else {
        /* Make the new node the first entry in the parent directory. */
        parent->first = node;
    }

    return result_ram_fs_node_ok(node);
}

/* Public functions */

struct ram_fs *ram_fs_new(struct alloc alloc)
{
    struct ram_fs *rfs;

    rfs = alloc_alloc(alloc, sizeof(*rfs), alignof(*rfs));
    if (!rfs) {
        pr_debug(STR("ramfs: Failed to allocate ram_fs structure "
                     "(size=%ld)\n"),
                 sizeof(*rfs));
        return NULL;
    }

    sz node_mem_size = RAM_FS_MAX_NODES_NUM * sizeof(struct ram_fs_node);
    void *node_mem =
        alloc_alloc(alloc, node_mem_size, alignof(struct ram_fs_node));
    if (!node_mem) {
        pr_debug(STR("ramfs: Failed to allocate node memory (size=%ld)\n"),
                 node_mem_size);
        alloc_free(alloc, rfs, sizeof(*rfs));
        return NULL;
    }
    rfs->node_alloc = pool_new(byte_array_new(node_mem, node_mem_size),
                               sizeof(struct ram_fs_node));

    sz scratch_mem_size = (sz) 4 * PATH_NAME_MAX_LEN;
    void *scratch_mem = alloc_alloc(alloc, scratch_mem_size, alignof(void *));
    if (!scratch_mem) {
        pr_debug(STR("ramfs: Failed to allocate scratch memory (size=%ld)\n"),
                 scratch_mem_size);
        alloc_free(alloc, node_mem, node_mem_size);
        alloc_free(alloc, rfs, sizeof(*rfs));
        return NULL;
    }
    rfs->scratch = arena_new(byte_array_new(scratch_mem, scratch_mem_size));

    rfs->data_alloc = alloc;

    /* The root must exists from the beginning as 'ram_fs_create_common' needs
     * it but can't create it itself.
     */
    struct ram_fs_node *root_dir = pool_alloc(&rfs->node_alloc);
    /* The pool was just created so there is surely enough memory. */
    assert(root_dir);
    root_dir->first = NULL;
    root_dir->next = NULL;
    root_dir->type = RAM_FS_TYPE_DIR;
    root_dir->name = STR("");
    root_dir->data = byte_buf_new(NULL, 0, 0);
    root_dir->flags = 0;
    root_dir->fs = rfs;

    rfs->root = root_dir;

    return rfs;
}

struct result_ram_fs_node ram_fs_create_dir(struct ram_fs_node *root,
                                            struct str dirpath,
                                            bool recursive)
{
    assert(root);
    return ram_fs_create_common(root, dirpath, RAM_FS_TYPE_DIR, recursive,
                                root->fs->scratch);
}

struct result_ram_fs_node ram_fs_create_file(struct ram_fs_node *root,
                                             struct str filepath,
                                             bool recursive)
{
    assert(root);

    /* Pre-allocate file data so that node creation cannot leave a linked node
     * with data.dat == NULL on allocation failure.
     */
    void *data = alloc_alloc(root->fs->data_alloc, RAM_FS_DEFAULT_FILE_SIZE,
                             alignof(void *));
    if (!data) {
        pr_debug(STR("ramfs: Failed to allocate file data for '%.*s' "
                     "(size=%d)\n"),
                 (int) filepath.len, filepath.dat, RAM_FS_DEFAULT_FILE_SIZE);
        return result_ram_fs_node_error(ENOMEM);
    }

    struct result_ram_fs_node node_res = ram_fs_create_common(
        root, filepath, RAM_FS_TYPE_FILE, recursive, root->fs->scratch);
    if (node_res.is_error) {
        alloc_free(root->fs->data_alloc, data, RAM_FS_DEFAULT_FILE_SIZE);
        return node_res;
    }
    struct ram_fs_node *node = result_ram_fs_node_checked(node_res);
    node->data = byte_buf_new(data, 0, RAM_FS_DEFAULT_FILE_SIZE);
    return result_ram_fs_node_ok(node);
}

struct result_ram_fs_node ram_fs_open(struct ram_fs_node *root,
                                      struct str filename)
{
    assert(root);

    struct arena scratch = root->fs->scratch;
    struct result_path_name path_res = path_name_parse(filename, &scratch);
    if (path_res.is_error) {
        pr_debug(STR("ramfs: Failed to parse path '%.*s': err=%d\n"),
                 (int) filename.len, filename.dat, path_res.code);
        return result_ram_fs_node_error(path_res.code);
    }

    struct path_name path = result_path_name_checked(path_res);

    if (path.n_components == 0)
        return result_ram_fs_node_ok(root);

    struct ram_fs_node *node = ram_fs_node_lookup(root, path);
    if (!node) {
        pr_debug(STR("ramfs: Node not found for path '%.*s'\n"),
                 (int) filename.len, filename.dat);
        return result_ram_fs_node_error(ENOENT);
    }

    return result_ram_fs_node_ok(node);
}

struct result_sz ram_fs_read(struct ram_fs_node *rfs_node,
                             struct byte_buf *bbuf,
                             sz offset)
{
    assert(rfs_node);
    assert(bbuf);

    if (rfs_node->type != RAM_FS_TYPE_FILE)
        return result_sz_error(EINVAL);

    if (offset > rfs_node->data.len)
        return result_sz_error(EINVAL);
    if (offset == rfs_node->data.len)
        return result_sz_ok(0);

    sz avail = rfs_node->data.len - offset;
    sz n_appended = byte_buf_append(
        bbuf, byte_view_new(rfs_node->data.dat + offset, avail));

    return result_sz_ok(n_appended);
}

struct result_sz ram_fs_write(struct ram_fs_node *rfs_node,
                              struct byte_view bview,
                              sz offset)
{
    assert(rfs_node);

    if (rfs_node->type != RAM_FS_TYPE_FILE)
        return result_sz_error(EINVAL);

    if (rfs_node->flags & RAM_FS_FLAG_READONLY)
        return result_sz_error(EROFS);

    /* Files are initialized to contain some data when created. */
    assert(rfs_node->data.dat && rfs_node->data.cap != 0);

    /* An offset outside of the file doesn't make sense. If the offset is equal
     * to the file length, the write operation appends to the file.
     */
    if (offset > rfs_node->data.len)
        return result_sz_error(EINVAL);

    if (bview.len + offset > rfs_node->data.cap) {
        /* The write operation exceeds the file capacity. Reallocate the data
         * buffer.
         */
        sz new_data_cap = 2 * rfs_node->data.cap;
        while (new_data_cap < bview.len + offset)
            new_data_cap *= 2;
        void *new_data = alloc_alloc(rfs_node->fs->data_alloc, new_data_cap,
                                     alignof(void *));
        if (!new_data)
            return result_sz_error(ENOMEM);
        struct byte_buf new_data_buf = byte_buf_new(new_data, 0, new_data_cap);
        byte_buf_append(&new_data_buf, byte_view_from_buf(rfs_node->data));
        alloc_free(rfs_node->fs->data_alloc, rfs_node->data.dat,
                   rfs_node->data.cap);
        rfs_node->data = new_data_buf;
    }

    /* At this point: str.len + offset <= rfs_node->data.cap => str.len <=
     * rfs_node->data.cap - offset
     */
    sz avail = rfs_node->data.cap - offset;
    /* Make sure the reallocation above worked as expected. */
    assert(bview.len <= avail);
    sz write_len = MIN(bview.len, avail);

    /* Ensure no out-of-bounds write on the buffer. These assertions may seem
     * redundant, but better safe than sorry.
     */
    assert(rfs_node->data.cap >= offset);
    assert(write_len <= rfs_node->data.cap - offset);
    struct byte_buf bb =
        byte_buf_new(rfs_node->data.dat + offset, 0, write_len);
    byte_buf_append(&bb, bview);
    assert(bb.len == write_len);
    rfs_node->data.len = MAX(rfs_node->data.len, offset + write_len);

    return result_sz_ok(write_len);
}

struct ram_fs_node *ram_fs_child_at(struct ram_fs_node *dir, sz index)
{
    if (!dir || dir->type != RAM_FS_TYPE_DIR)
        return NULL;
    struct ram_fs_node *child = dir->first;
    for (sz i = 0; i < index && child; i++)
        child = child->next;
    return child;
}

#if CONFIG_RAMFS_WRITABLE

struct result ram_fs_unlink(struct ram_fs_node *root, struct str path)
{
    assert(root);

    struct arena scratch = root->fs->scratch;
    struct result_path_name path_res = path_name_parse(path, &scratch);
    if (path_res.is_error)
        return result_error(path_res.code);

    struct path_name pn = result_path_name_checked(path_res);
    if (pn.n_components == 0)
        return result_error(EINVAL); /* can't unlink root */

    /* Find parent directory. */
    struct path_name parent_pn = pn;
    parent_pn.n_components--;
    struct ram_fs_node *parent = ram_fs_node_lookup(root, parent_pn);
    if (!parent || parent->type != RAM_FS_TYPE_DIR)
        return result_error(ENOENT);

    struct str target_name = pn.components[pn.n_components - 1];

    /* Walk sibling list to find and unlink the target. */
    struct ram_fs_node *prev = NULL;
    struct ram_fs_node *curr = parent->first;
    while (curr) {
        if (str_is_equal(curr->name, target_name)) {
            if (curr->type == RAM_FS_TYPE_DIR)
                return result_error(EISDIR);
            if (curr->flags & RAM_FS_FLAG_READONLY)
                return result_error(EROFS);

            /* Unlink from sibling list. */
            if (prev)
                prev->next = curr->next;
            else
                parent->first = curr->next;

            /* Free file data and return node to pool. */
            if (curr->data.dat)
                alloc_free(curr->fs->data_alloc, curr->data.dat,
                           curr->data.cap);
            pool_free(&curr->fs->node_alloc, curr);
            return result_ok();
        }
        prev = curr;
        curr = curr->next;
    }

    return result_error(ENOENT);
}

struct result ram_fs_rmdir(struct ram_fs_node *root, struct str path)
{
    assert(root);

    struct arena scratch = root->fs->scratch;
    struct result_path_name path_res = path_name_parse(path, &scratch);
    if (path_res.is_error)
        return result_error(path_res.code);

    struct path_name pn = result_path_name_checked(path_res);
    if (pn.n_components == 0)
        return result_error(EINVAL); /* can't remove root */

    /* Find parent directory. */
    struct path_name parent_pn = pn;
    parent_pn.n_components--;
    struct ram_fs_node *parent = ram_fs_node_lookup(root, parent_pn);
    if (!parent || parent->type != RAM_FS_TYPE_DIR)
        return result_error(ENOENT);

    struct str target_name = pn.components[pn.n_components - 1];

    struct ram_fs_node *prev = NULL;
    struct ram_fs_node *curr = parent->first;
    while (curr) {
        if (str_is_equal(curr->name, target_name)) {
            if (curr->type != RAM_FS_TYPE_DIR)
                return result_error(ENOTDIR);
            if (curr->flags & RAM_FS_FLAG_READONLY)
                return result_error(EROFS);
            if (curr->first != NULL)
                return result_error(ENOTEMPTY);

            /* Unlink from sibling list. */
            if (prev)
                prev->next = curr->next;
            else
                parent->first = curr->next;

            pool_free(&curr->fs->node_alloc, curr);
            return result_ok();
        }
        prev = curr;
        curr = curr->next;
    }

    return result_error(ENOENT);
}

struct result ram_fs_truncate(struct ram_fs_node *node)
{
    assert(node);
    if (node->type != RAM_FS_TYPE_FILE)
        return result_error(EINVAL);
    if (node->flags & RAM_FS_FLAG_READONLY)
        return result_error(EROFS);
    node->data.len = 0;
    return result_ok();
}

#endif /* CONFIG_RAMFS_WRITABLE */

/* VFS adapter */

static struct result_vfs_file ramfs_vfs_open(void *ctx, struct str path)
{
    struct ram_fs *rfs = ctx;
    struct result_ram_fs_node res = ram_fs_open(rfs->root, path);
    if (res.is_error)
        return result_vfs_file_error(res.code);

    struct vfs_file f = {
        .private_data = result_ram_fs_node_checked(res),
        .mount_idx = 0, /* filled by vfs_open */
    };
    return result_vfs_file_ok(f);
}

static void ramfs_vfs_close(void *ctx __unused, struct vfs_file *f __unused)
{
    /* ramfs nodes are persistent; nothing to free. */
}

static struct result_sz ramfs_vfs_read(void *ctx __unused,
                                       struct vfs_file *f,
                                       struct byte_buf *buf,
                                       sz off)
{
    struct ram_fs_node *node = f->private_data;
    return ram_fs_read(node, buf, off);
}

static struct result_sz ramfs_vfs_write(void *ctx __unused,
                                        struct vfs_file *f,
                                        struct byte_view data,
                                        sz off)
{
    struct ram_fs_node *node = f->private_data;
    return ram_fs_write(node, data, off);
}

static struct result_vfs_stat ramfs_vfs_stat(void *ctx, struct str path)
{
    struct ram_fs *rfs = ctx;
    struct result_ram_fs_node res = ram_fs_open(rfs->root, path);
    if (res.is_error)
        return result_vfs_stat_error(res.code);

    struct ram_fs_node *node = result_ram_fs_node_checked(res);
    bool is_file = node->type == RAM_FS_TYPE_FILE;
    struct vfs_stat st = {
        .size = is_file ? node->data.len : 0,
        .type = is_file ? VFS_TYPE_FILE : VFS_TYPE_DIR,
        .flags = is_file ? 0 : VFS_FLAG_NOSEEK,
        .etag = node->etag,
    };
    return result_vfs_stat_ok(st);
}

static struct result_vfs_dirent ramfs_vfs_readdir(void *ctx,
                                                  struct str dirpath,
                                                  sz index)
{
    struct ram_fs *rfs = ctx;
    struct result_ram_fs_node res = ram_fs_open(rfs->root, dirpath);
    if (res.is_error)
        return result_vfs_dirent_error(res.code);

    struct ram_fs_node *node = result_ram_fs_node_checked(res);
    if (node->type != RAM_FS_TYPE_DIR)
        return result_vfs_dirent_error(ENOTDIR);

    /* Walk linked list to the Nth child. */
    struct ram_fs_node *child = node->first;
    for (sz i = 0; i < index && child; i++)
        child = child->next;

    if (!child)
        return result_vfs_dirent_error(ENOENT);

    struct vfs_dirent d = {
        .name = child->name,
        .type =
            (child->type == RAM_FS_TYPE_FILE) ? VFS_TYPE_FILE : VFS_TYPE_DIR,
    };
    return result_vfs_dirent_ok(d);
}

static struct result ramfs_vfs_create(void *ctx, struct str path)
{
    struct ram_fs *rfs = ctx;
    struct result_ram_fs_node res = ram_fs_create_file(rfs->root, path, true);
    if (res.is_error)
        return result_error(res.code);
    return result_ok();
}

static struct result ramfs_vfs_unlink(void *ctx, struct str path)
{
#if CONFIG_RAMFS_WRITABLE
    struct ram_fs *rfs = ctx;
    return ram_fs_unlink(rfs->root, path);
#else
    (void) ctx;
    (void) path;
    return result_error(EROFS);
#endif
}

static struct result ramfs_vfs_mkdir(void *ctx, struct str path)
{
    struct ram_fs *rfs = ctx;
    struct result_ram_fs_node res = ram_fs_create_dir(rfs->root, path, false);
    if (res.is_error)
        return result_error(res.code);
    return result_ok();
}

static struct result ramfs_vfs_rmdir(void *ctx, struct str path)
{
#if CONFIG_RAMFS_WRITABLE
    struct ram_fs *rfs = ctx;
    return ram_fs_rmdir(rfs->root, path);
#else
    (void) ctx;
    (void) path;
    return result_error(EROFS);
#endif
}

struct vfs_ops ramfs_vfs_ops(void)
{
    return (struct vfs_ops) {
        .open = ramfs_vfs_open,
        .close = ramfs_vfs_close,
        .read = ramfs_vfs_read,
        .write = ramfs_vfs_write,
        .stat = ramfs_vfs_stat,
        .readdir = ramfs_vfs_readdir,
        .create = ramfs_vfs_create,
        .unlink = ramfs_vfs_unlink,
        .mkdir = ramfs_vfs_mkdir,
        .rmdir = ramfs_vfs_rmdir,
    };
}

/* Tests */

#include __INC_TEST(ramfs)
