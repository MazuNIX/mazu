/* SPDX-License-Identifier: MIT */
/* Simple Filesystem (SFS) implementation.
 *
 * On-disk format:
 *   Sector 0         - Superblock (magic, geometry)
 *   Sector 1..B      - Bitmap (1 bit/sector)
 *   Sector B+1..D    - Directory table (64 bytes/entry)
 *   Sector D+1..N    - Data region
 *
 * Contiguous allocation: each file occupies a contiguous run of sectors.
 * Flat directory: 256 fixed-size entries with parent_idx linkage.
 * Crash consistency via bcache ordered flush (data before metadata).
 */

#include "sfs.h"
#include <mazu/assert.h>
#include <mazu/base.h>
#include <mazu/kvalloc.h>
#include <mazu/print.h>
#include <mazu/string.h>
#include "bcache.h"

#define SFS_MAX_DIRENTS 256
#define SFS_DIRENTS_PER_SECTOR (BCACHE_SECTOR_SIZE / sizeof(struct sfs_dirent))

/* Length of a NUL-terminated name (max 48 bytes). */
static sz sfs_namelen(const char *s)
{
    sz n = 0;
    while (n < 48 && s[n] != '\0')
        n++;
    return n;
}

/* Bitmap helpers */

static bool bitmap_get(struct bcache *cache,
                       struct sfs_super *super,
                       u32 sector)
{
    u32 bit_off = sector;
    u32 bm_sector = super->bitmap_start + bit_off / (BCACHE_SECTOR_SIZE * 8);
    u32 byte_off = (bit_off % (BCACHE_SECTOR_SIZE * 8)) / 8;
    u32 bit_pos = bit_off % 8;

    struct buf *b = bcache_read(cache, bm_sector);
    if (!b)
        return true; /* treat as allocated on error */
    bool set = (b->data[byte_off] >> bit_pos) & 1;
    bcache_release(b);
    return set;
}

static void bitmap_set(struct bcache *cache,
                       struct sfs_super *super,
                       u32 sector,
                       bool val)
{
    u32 bit_off = sector;
    u32 bm_sector = super->bitmap_start + bit_off / (BCACHE_SECTOR_SIZE * 8);
    u32 byte_off = (bit_off % (BCACHE_SECTOR_SIZE * 8)) / 8;
    u32 bit_pos = bit_off % 8;

    struct buf *b = bcache_read(cache, bm_sector);
    if (!b)
        return;
    if (val)
        b->data[byte_off] |= (byte) (1 << bit_pos);
    else
        b->data[byte_off] &= (byte) ~(1 << bit_pos);
    bcache_mark_dirty(b);
    bcache_mark_meta(b);
    bcache_release(b);
}

/* Allocate a contiguous run of 'count' free sectors.  Returns start sector or 0
 * on failure.
 */
static u32 bitmap_alloc(struct bcache *cache,
                        struct sfs_super *super,
                        u32 count)
{
    u32 run_start = super->data_start;
    u32 run_len = 0;

    for (u32 s = super->data_start; s < super->total_sectors; s++) {
        if (!bitmap_get(cache, super, s)) {
            if (run_len == 0)
                run_start = s;
            run_len++;
            if (run_len == count) {
                /* Mark all sectors allocated. */
                for (u32 i = run_start; i < run_start + count; i++)
                    bitmap_set(cache, super, i, true);
                super->free_sectors -= count;
                return run_start;
            }
        } else {
            run_len = 0;
        }
    }
    return 0; /* no space */
}

static void bitmap_free(struct bcache *cache,
                        struct sfs_super *super,
                        u32 start,
                        u32 count)
{
    for (u32 i = start; i < start + count; i++) {
        bitmap_set(cache, super, i, false);
        super->free_sectors++;
    }
}

/* Directory entry helpers */

static struct sfs_dirent *sfs_read_dirent(struct bcache *cache,
                                          struct sfs_super *super,
                                          u32 idx,
                                          struct buf **out_buf)
{
    u32 entries_per_sector = (u32) SFS_DIRENTS_PER_SECTOR;
    u32 sector = super->dir_start + idx / entries_per_sector;
    u32 off = (idx % entries_per_sector) * sizeof(struct sfs_dirent);

    struct buf *b = bcache_read(cache, sector);
    if (!b) {
        *out_buf = NULL;
        return NULL;
    }
    *out_buf = b;
    return (struct sfs_dirent *) (b->data + off);
}

/* Find a free directory entry. Returns index or SFS_MAX_DIRENTS on failure. */
static u32 sfs_alloc_dirent(struct bcache *cache, struct sfs_super *super)
{
    for (u32 i = 0; i < super->n_dirents; i++) {
        struct buf *b;
        struct sfs_dirent *d = sfs_read_dirent(cache, super, i, &b);
        if (!d)
            continue;
        bool is_free = (d->type == SFS_TYPE_FREE);
        bcache_release(b);
        if (is_free)
            return i;
    }
    return SFS_MAX_DIRENTS;
}

/* Resolve a path relative to the SFS root.  Returns dirent index or
 * SFS_MAX_DIRENTS.
 */
static u32 sfs_lookup(struct bcache *cache,
                      struct sfs_super *super,
                      struct str path)
{
    /* Skip leading slash. */
    if (path.len > 0 && path.dat[0] == '/') {
        path.dat++;
        path.len--;
    }

    /* Empty path = root directory (index 0). */
    if (path.len == 0)
        return 0;

    /* Strip trailing slash. */
    if (path.len > 0 && path.dat[path.len - 1] == '/') {
        path.len--;
    }

    u16 parent = 0; /* root */

    while (path.len > 0) {
        /* Extract next component. */
        sz sep = 0;
        while (sep < path.len && path.dat[sep] != '/')
            sep++;
        struct str component = str_new(path.dat, sep);

        /* Search directory entries for this component under parent. */
        u32 found = SFS_MAX_DIRENTS;
        for (u32 i = 0; i < super->n_dirents; i++) {
            struct buf *b;
            struct sfs_dirent *d = sfs_read_dirent(cache, super, i, &b);
            if (!d)
                continue;
            if (d->type != SFS_TYPE_FREE && d->parent_idx == parent) {
                struct str dname = str_new(d->name, sfs_namelen(d->name));
                if (str_is_equal(dname, component))
                    found = i;
            }
            bcache_release(b);
            if (found != SFS_MAX_DIRENTS)
                break;
        }

        if (found == SFS_MAX_DIRENTS)
            return SFS_MAX_DIRENTS;

        /* Advance. */
        if (sep < path.len)
            sep++; /* skip '/' */
        path.dat += sep;
        path.len -= sep;
        parent = (u16) found;
    }

    return (u32) parent;
}

/* Find parent dir index and extract basename from path. */
static u32 sfs_lookup_parent(struct bcache *cache,
                             struct sfs_super *super,
                             struct str path,
                             struct str *out_name)
{
    /* Skip leading slash. */
    if (path.len > 0 && path.dat[0] == '/') {
        path.dat++;
        path.len--;
    }

    /* Strip trailing slash. */
    if (path.len > 0 && path.dat[path.len - 1] == '/')
        path.len--;

    /* Find last slash to split parent/name. */
    sz last_slash = 0;
    bool has_slash = false;
    for (sz i = 0; i < path.len; i++) {
        if (path.dat[i] == '/') {
            last_slash = i;
            has_slash = true;
        }
    }

    if (!has_slash) {
        /* File is directly in root. */
        *out_name = path;
        return 0;
    }

    struct str parent_path = str_new(path.dat, last_slash);
    *out_name = str_new(path.dat + last_slash + 1, path.len - last_slash - 1);

    /* Lookup the parent directory. */
    u16 parent = 0;
    struct str rest = parent_path;
    while (rest.len > 0) {
        sz sep = 0;
        while (sep < rest.len && rest.dat[sep] != '/')
            sep++;
        struct str component = str_new(rest.dat, sep);

        u32 found = SFS_MAX_DIRENTS;
        for (u32 i = 0; i < super->n_dirents; i++) {
            struct buf *b;
            struct sfs_dirent *d = sfs_read_dirent(cache, super, i, &b);
            if (!d)
                continue;
            if (d->type == SFS_TYPE_DIR && d->parent_idx == parent) {
                struct str dname = str_new(d->name, sfs_namelen(d->name));
                if (str_is_equal(dname, component))
                    found = i;
            }
            bcache_release(b);
            if (found != SFS_MAX_DIRENTS)
                break;
        }

        if (found == SFS_MAX_DIRENTS)
            return SFS_MAX_DIRENTS;

        if (sep < rest.len)
            sep++;
        rest.dat += sep;
        rest.len -= sep;
        parent = (u16) found;
    }

    return (u32) parent;
}

/* Superblock helpers */

static struct result sfs_write_super(struct bcache *cache,
                                     struct sfs_super *super)
{
    struct buf *b = bcache_read(cache, 0);
    if (!b)
        return result_error(EIO);
    memcpy(b->data, super, sizeof(struct sfs_super));
    bcache_mark_dirty(b);
    bcache_mark_meta(b);
    bcache_release(b);
    return result_ok();
}

static struct result sfs_read_super(struct bcache *cache,
                                    struct sfs_super *super)
{
    struct buf *b = bcache_read(cache, 0);
    if (!b)
        return result_error(EIO);
    memcpy(super, b->data, sizeof(struct sfs_super));
    bcache_release(b);
    return result_ok();
}

/* Format */

struct result sfs_format(struct bcache *cache, u32 total_sectors)
{
    assert(cache);

    u32 dir_entries = SFS_MAX_DIRENTS;
    u32 dir_bytes = dir_entries * sizeof(struct sfs_dirent);
    u32 bitmap_sectors =
        (total_sectors + BCACHE_SECTOR_SIZE * 8 - 1) / (BCACHE_SECTOR_SIZE * 8);
    u32 dir_start = 1 + bitmap_sectors;
    u32 dir_sectors = (dir_bytes + BCACHE_SECTOR_SIZE - 1) / BCACHE_SECTOR_SIZE;
    u32 data_start = dir_start + dir_sectors;
    struct sfs_super super = {
        .magic = SFS_MAGIC,
        .version = SFS_VERSION,
        .total_sectors = total_sectors,
        .bitmap_start = 1,
        .bitmap_sectors = bitmap_sectors,
        .dir_start = dir_start,
        .dir_sectors = dir_sectors,
        .data_start = data_start,
        .n_dirents = dir_entries,
        .free_sectors = total_sectors - data_start,
    };

    /* Write superblock. */
    struct result res = sfs_write_super(cache, &super);
    if (res.is_error)
        return res;

    /* Zero bitmap. */
    for (u32 s = super.bitmap_start;
         s < super.bitmap_start + super.bitmap_sectors; s++) {
        struct buf *b = bcache_read(cache, s);
        if (!b)
            return result_error(EIO);
        memset(b->data, 0, BCACHE_SECTOR_SIZE);
        bcache_mark_dirty(b);
        bcache_mark_meta(b);
        bcache_release(b);
    }

    /* Mark reserved sectors (0 through data_start-1) as allocated in bitmap. */
    for (u32 s = 0; s < super.data_start; s++)
        bitmap_set(cache, &super, s, true);

    /* Zero directory table. */
    for (u32 s = super.dir_start; s < super.dir_start + super.dir_sectors;
         s++) {
        struct buf *b = bcache_read(cache, s);
        if (!b)
            return result_error(EIO);
        memset(b->data, 0, BCACHE_SECTOR_SIZE);
        bcache_mark_dirty(b);
        bcache_mark_meta(b);
        bcache_release(b);
    }

    /* Create root directory entry at index 0. */
    struct buf *db;
    struct sfs_dirent *root = sfs_read_dirent(cache, &super, 0, &db);
    if (!root)
        return result_error(EIO);
    memset(root, 0, sizeof(*root));
    root->name[0] = '/';
    root->name[1] = '\0';
    root->type = SFS_TYPE_DIR;
    root->parent_idx = SFS_ROOT_PARENT;
    bcache_mark_dirty(db);
    bcache_mark_meta(db);
    bcache_release(db);

    return bcache_sync(cache);
}

/* Mount and fsck */

struct result_sfs sfs_mount(struct bcache *cache)
{
    assert(cache);

    struct sfs_super super;
    struct result res = sfs_read_super(cache, &super);
    if (res.is_error)
        return result_sfs_error(res.code);

    if (super.magic != SFS_MAGIC || super.version != SFS_VERSION)
        return result_sfs_error(EINVAL);

    struct option_byte_array mem =
        kvalloc_alloc(sizeof(struct sfs), alignof(struct sfs));
    if (mem.is_none)
        return result_sfs_error(ENOMEM);

    struct sfs *fs = byte_array_ptr(option_byte_array_checked(mem));
    fs->cache = cache;
    fs->super = super;
    fs->lock = (spinlock_t) SPINLOCK_INITIALIZER;

    pr_info(STR("sfs: mounted (%u sectors, %u free, %u dirents)\n"),
            super.total_sectors, super.free_sectors, super.n_dirents);

    return result_sfs_ok(fs);
}

struct result sfs_fsck(struct sfs *fs)
{
    assert(fs);
    struct bcache *cache = fs->cache;
    struct sfs_super *super = &fs->super;

    /* Verify every non-free dirent's sectors are marked allocated. */
    for (u32 i = 0; i < super->n_dirents; i++) {
        struct buf *b;
        struct sfs_dirent *d = sfs_read_dirent(cache, super, i, &b);
        if (!d)
            continue;
        if (d->type == SFS_TYPE_FILE && d->size > 0) {
            u32 nsectors =
                (d->size + BCACHE_SECTOR_SIZE - 1) / BCACHE_SECTOR_SIZE;
            for (u32 s = d->start_sector; s < d->start_sector + nsectors; s++) {
                if (!bitmap_get(cache, super, s)) {
                    bcache_release(b);
                    pr_warn(STR("sfs: fsck: dirent %u sector %u not "
                                "allocated\n"),
                            i, s);
                    return result_error(EIO);
                }
            }
        }
        bcache_release(b);
    }

    return result_ok();
}

/* VFS adapter */

struct sfs_file {
    u32 dirent_idx;
};

static struct result_vfs_file sfs_vfs_open(void *ctx, struct str path)
{
    struct sfs *fs = ctx;
    u32 idx = sfs_lookup(fs->cache, &fs->super, path);
    if (idx == SFS_MAX_DIRENTS)
        return result_vfs_file_error(ENOENT);

    /* Allocate sfs_file handle. */
    struct option_byte_array mem =
        kvalloc_alloc(sizeof(struct sfs_file), alignof(struct sfs_file));
    if (mem.is_none)
        return result_vfs_file_error(ENOMEM);
    struct sfs_file *sf = byte_array_ptr(option_byte_array_checked(mem));
    sf->dirent_idx = idx;

    struct vfs_file f = {.private_data = sf, .mount_idx = 0};
    return result_vfs_file_ok(f);
}

static void sfs_vfs_close(void *ctx __unused, struct vfs_file *f)
{
    if (f && f->private_data) {
        /* Free the sfs_file handle. */
        struct sfs_file *sf = f->private_data;
        struct byte_array ba =
            byte_array_new((byte *) sf, sizeof(struct sfs_file));
        kvalloc_free(ba);
        f->private_data = NULL;
    }
}

static struct result_sz sfs_vfs_read(void *ctx,
                                     struct vfs_file *f,
                                     struct byte_buf *buf,
                                     sz off)
{
    struct sfs *fs = ctx;
    struct sfs_file *sf = f->private_data;

    struct buf *db;
    struct sfs_dirent *d =
        sfs_read_dirent(fs->cache, &fs->super, sf->dirent_idx, &db);
    if (!d)
        return result_sz_error(EIO);
    if (d->type == SFS_TYPE_DIR) {
        bcache_release(db);
        return result_sz_error(EISDIR);
    }

    u32 size = d->size;
    u32 start = d->start_sector;
    bcache_release(db);

    if ((sz) off >= (sz) size)
        return result_sz_ok(0);

    sz to_read = (sz) size - off;
    sz avail = (sz) buf->cap - (sz) buf->len;
    if (to_read > avail)
        to_read = avail;

    sz total = 0;
    sz file_off = off;
    while (total < to_read) {
        u32 sector = start + (u32) (file_off / BCACHE_SECTOR_SIZE);
        sz sec_off = file_off % BCACHE_SECTOR_SIZE;
        sz chunk = (sz) BCACHE_SECTOR_SIZE - sec_off;
        if (chunk > to_read - total)
            chunk = to_read - total;

        struct buf *sb = bcache_read(fs->cache, sector);
        if (!sb)
            return result_sz_error(EIO);
        memcpy(buf->dat + buf->len, sb->data + sec_off, chunk);
        bcache_release(sb);

        buf->len += chunk;
        total += chunk;
        file_off += chunk;
    }

    return result_sz_ok(total);
}

static struct result_sz sfs_vfs_write(void *ctx,
                                      struct vfs_file *f,
                                      struct byte_view data,
                                      sz off)
{
    struct sfs *fs = ctx;
    struct sfs_file *sf = f->private_data;

    u64 flags = spin_lock_irqsave(&fs->lock);

    struct buf *db;
    struct sfs_dirent *d =
        sfs_read_dirent(fs->cache, &fs->super, sf->dirent_idx, &db);
    if (!d) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_sz_error(EIO);
    }
    if (d->type == SFS_TYPE_DIR) {
        bcache_release(db);
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_sz_error(EISDIR);
    }

    sz end_pos = off + data.len;
    sz new_size = (end_pos > (sz) d->size) ? end_pos : (sz) d->size;
    u32 old_nsectors =
        (d->size > 0) ? (d->size + BCACHE_SECTOR_SIZE - 1) / BCACHE_SECTOR_SIZE
                      : 0;
    u32 new_nsectors =
        (new_size > 0)
            ? ((u32) new_size + BCACHE_SECTOR_SIZE - 1) / BCACHE_SECTOR_SIZE
            : 0;

    u32 start = d->start_sector;

    /* Need to grow allocation? */
    if (new_nsectors > old_nsectors) {
        /* Free old and allocate new contiguous run. */
        if (old_nsectors > 0)
            bitmap_free(fs->cache, &fs->super, start, old_nsectors);

        u32 new_start = bitmap_alloc(fs->cache, &fs->super, new_nsectors);
        if (new_start == 0) {
            /* Restore old allocation on failure. */
            if (old_nsectors > 0) {
                for (u32 i = start; i < start + old_nsectors; i++)
                    bitmap_set(fs->cache, &fs->super, i, true);
            }
            bcache_release(db);
            spin_unlock_irqrestore(&fs->lock, flags);
            return result_sz_error(ENOSPC);
        }

        /* Copy old data to new location if needed. */
        if (old_nsectors > 0) {
            for (u32 s = 0; s < old_nsectors; s++) {
                struct buf *old_b = bcache_read(fs->cache, start + s);
                struct buf *new_b = bcache_read(fs->cache, new_start + s);
                if (old_b && new_b) {
                    memcpy(new_b->data, old_b->data, BCACHE_SECTOR_SIZE);
                    bcache_mark_dirty(new_b);
                }
                if (old_b)
                    bcache_release(old_b);
                if (new_b)
                    bcache_release(new_b);
            }
        }

        start = new_start;
        d->start_sector = start;
    }

    bool sectors_changed = (new_nsectors != old_nsectors);
    d->size = (u32) new_size;
    bcache_mark_dirty(db);
    bcache_mark_meta(db);
    bcache_release(db);

    if (sectors_changed)
        sfs_write_super(fs->cache, &fs->super);

    spin_unlock_irqrestore(&fs->lock, flags);

    /* Write data to sectors. */
    sz file_off = off;
    sz written = 0;
    while (written < data.len) {
        u32 sector = start + (u32) (file_off / BCACHE_SECTOR_SIZE);
        sz sec_off = file_off % BCACHE_SECTOR_SIZE;
        sz chunk = (sz) BCACHE_SECTOR_SIZE - sec_off;
        if (chunk > data.len - written)
            chunk = data.len - written;

        struct buf *sb = bcache_read(fs->cache, sector);
        if (!sb)
            return result_sz_error(EIO);
        memcpy(sb->data + sec_off, data.dat + written, chunk);
        bcache_mark_dirty(sb);
        bcache_release(sb);

        written += chunk;
        file_off += chunk;
    }

    bcache_sync(fs->cache);

    return result_sz_ok((sz) data.len);
}

static struct result_vfs_stat sfs_vfs_stat(void *ctx, struct str path)
{
    struct sfs *fs = ctx;
    u32 idx = sfs_lookup(fs->cache, &fs->super, path);
    if (idx == SFS_MAX_DIRENTS)
        return result_vfs_stat_error(ENOENT);

    struct buf *db;
    struct sfs_dirent *d = sfs_read_dirent(fs->cache, &fs->super, idx, &db);
    if (!d)
        return result_vfs_stat_error(EIO);

    bool is_dir = d->type == SFS_TYPE_DIR;
    struct vfs_stat st = {
        .size = d->size,
        .type = is_dir ? VFS_TYPE_DIR : VFS_TYPE_FILE,
        .flags = is_dir ? VFS_FLAG_NOSEEK : 0,
        .etag = 0,
    };
    bcache_release(db);

    return result_vfs_stat_ok(st);
}

static struct result_vfs_dirent sfs_vfs_readdir(void *ctx,
                                                struct str dirpath,
                                                sz index)
{
    struct sfs *fs = ctx;
    u32 dir_idx = sfs_lookup(fs->cache, &fs->super, dirpath);
    if (dir_idx == SFS_MAX_DIRENTS)
        return result_vfs_dirent_error(ENOENT);

    /* Verify target is a directory (index 0 is root, always a dir). */
    if (dir_idx != 0) {
        struct buf *db;
        struct sfs_dirent *dd =
            sfs_read_dirent(fs->cache, &fs->super, dir_idx, &db);
        if (!dd)
            return result_vfs_dirent_error(EIO);
        if (dd->type != SFS_TYPE_DIR) {
            bcache_release(db);
            return result_vfs_dirent_error(ENOTDIR);
        }
        bcache_release(db);
    }

    /* Count children until reaching the Nth one. */
    sz count = 0;
    for (u32 i = 0; i < fs->super.n_dirents; i++) {
        struct buf *b;
        struct sfs_dirent *d = sfs_read_dirent(fs->cache, &fs->super, i, &b);
        if (!d)
            continue;
        if (d->type != SFS_TYPE_FREE && d->parent_idx == (u16) dir_idx) {
            if (count == (sz) index) {
                /* Copy the name before releasing the bcache buf so
                 * the returned str does not point into reclaimable
                 * cache memory.
                 */
                sz nlen = sfs_namelen(d->name);
                u8 type =
                    (d->type == SFS_TYPE_DIR) ? VFS_TYPE_DIR : VFS_TYPE_FILE;
                for (sz j = 0; j < nlen; j++)
                    fs->readdir_name[j] = d->name[j];
                bcache_release(b);
                return result_vfs_dirent_ok((struct vfs_dirent) {
                    .name = str_new(fs->readdir_name, nlen),
                    .type = type,
                });
            }
            count++;
        }
        bcache_release(b);
    }

    return result_vfs_dirent_error(ENOENT);
}

static struct result sfs_vfs_create(void *ctx, struct str path)
{
    struct sfs *fs = ctx;

    u64 flags = spin_lock_irqsave(&fs->lock);

    /* Check if already exists. */
    u32 existing = sfs_lookup(fs->cache, &fs->super, path);
    if (existing != SFS_MAX_DIRENTS) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(EEXIST);
    }

    /* Find parent and basename. */
    struct str name;
    u32 parent = sfs_lookup_parent(fs->cache, &fs->super, path, &name);
    if (parent == SFS_MAX_DIRENTS) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(ENOENT);
    }
    if (name.len == 0 || name.len > SFS_NAME_MAX) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(ENAMETOOLONG);
    }

    u32 slot = sfs_alloc_dirent(fs->cache, &fs->super);
    if (slot == SFS_MAX_DIRENTS) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(ENOSPC);
    }

    struct buf *db;
    struct sfs_dirent *d = sfs_read_dirent(fs->cache, &fs->super, slot, &db);
    if (!d) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(EIO);
    }

    memset(d, 0, sizeof(*d));
    sz copy_len = name.len < SFS_NAME_MAX ? name.len : SFS_NAME_MAX;
    memcpy(d->name, name.dat, copy_len);
    d->name[copy_len] = '\0';
    d->type = SFS_TYPE_FILE;
    d->parent_idx = (u16) parent;
    d->size = 0;
    d->start_sector = 0;

    bcache_mark_dirty(db);
    bcache_mark_meta(db);
    bcache_release(db);

    bcache_sync(fs->cache);
    spin_unlock_irqrestore(&fs->lock, flags);

    return result_ok();
}

static struct result sfs_vfs_unlink(void *ctx, struct str path)
{
    struct sfs *fs = ctx;

    u64 flags = spin_lock_irqsave(&fs->lock);

    u32 idx = sfs_lookup(fs->cache, &fs->super, path);
    if (idx == SFS_MAX_DIRENTS) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(ENOENT);
    }

    struct buf *db;
    struct sfs_dirent *d = sfs_read_dirent(fs->cache, &fs->super, idx, &db);
    if (!d) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(EIO);
    }

    if (d->type == SFS_TYPE_DIR) {
        bcache_release(db);
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(EISDIR);
    }

    /* Free data sectors. */
    if (d->size > 0) {
        u32 nsectors = (d->size + BCACHE_SECTOR_SIZE - 1) / BCACHE_SECTOR_SIZE;
        bitmap_free(fs->cache, &fs->super, d->start_sector, nsectors);
    }

    d->type = SFS_TYPE_FREE;
    bcache_mark_dirty(db);
    bcache_mark_meta(db);
    bcache_release(db);

    sfs_write_super(fs->cache, &fs->super);
    bcache_sync(fs->cache);
    spin_unlock_irqrestore(&fs->lock, flags);

    return result_ok();
}

static struct result sfs_vfs_mkdir(void *ctx, struct str path)
{
    struct sfs *fs = ctx;

    u64 flags = spin_lock_irqsave(&fs->lock);

    u32 existing = sfs_lookup(fs->cache, &fs->super, path);
    if (existing != SFS_MAX_DIRENTS) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(EEXIST);
    }

    struct str name;
    u32 parent = sfs_lookup_parent(fs->cache, &fs->super, path, &name);
    if (parent == SFS_MAX_DIRENTS) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(ENOENT);
    }
    if (name.len == 0 || name.len > SFS_NAME_MAX) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(ENAMETOOLONG);
    }

    u32 slot = sfs_alloc_dirent(fs->cache, &fs->super);
    if (slot == SFS_MAX_DIRENTS) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(ENOSPC);
    }

    struct buf *db;
    struct sfs_dirent *d = sfs_read_dirent(fs->cache, &fs->super, slot, &db);
    if (!d) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(EIO);
    }

    memset(d, 0, sizeof(*d));
    sz copy_len = name.len < SFS_NAME_MAX ? name.len : SFS_NAME_MAX;
    memcpy(d->name, name.dat, copy_len);
    d->name[copy_len] = '\0';
    d->type = SFS_TYPE_DIR;
    d->parent_idx = (u16) parent;

    bcache_mark_dirty(db);
    bcache_mark_meta(db);
    bcache_release(db);

    bcache_sync(fs->cache);
    spin_unlock_irqrestore(&fs->lock, flags);

    return result_ok();
}

static struct result sfs_vfs_rmdir(void *ctx, struct str path)
{
    struct sfs *fs = ctx;

    u64 flags = spin_lock_irqsave(&fs->lock);

    u32 idx = sfs_lookup(fs->cache, &fs->super, path);
    if (idx == SFS_MAX_DIRENTS || idx == 0) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(ENOENT);
    }

    struct buf *db;
    struct sfs_dirent *d = sfs_read_dirent(fs->cache, &fs->super, idx, &db);
    if (!d) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(EIO);
    }

    if (d->type != SFS_TYPE_DIR) {
        bcache_release(db);
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(ENOTDIR);
    }
    bcache_release(db);

    /* Check directory is empty. */
    for (u32 i = 0; i < fs->super.n_dirents; i++) {
        struct buf *cb;
        struct sfs_dirent *cd = sfs_read_dirent(fs->cache, &fs->super, i, &cb);
        if (!cd)
            continue;
        if (cd->type != SFS_TYPE_FREE && cd->parent_idx == (u16) idx) {
            bcache_release(cb);
            spin_unlock_irqrestore(&fs->lock, flags);
            return result_error(ENOTEMPTY);
        }
        bcache_release(cb);
    }

    /* Free the entry. */
    d = sfs_read_dirent(fs->cache, &fs->super, idx, &db);
    if (!d) {
        spin_unlock_irqrestore(&fs->lock, flags);
        return result_error(EIO);
    }
    d->type = SFS_TYPE_FREE;
    bcache_mark_dirty(db);
    bcache_mark_meta(db);
    bcache_release(db);

    bcache_sync(fs->cache);
    spin_unlock_irqrestore(&fs->lock, flags);

    return result_ok();
}

struct vfs_ops sfs_vfs_ops(void)
{
    return (struct vfs_ops) {
        .open = sfs_vfs_open,
        .close = sfs_vfs_close,
        .read = sfs_vfs_read,
        .write = sfs_vfs_write,
        .stat = sfs_vfs_stat,
        .readdir = sfs_vfs_readdir,
        .create = sfs_vfs_create,
        .unlink = sfs_vfs_unlink,
        .mkdir = sfs_vfs_mkdir,
        .rmdir = sfs_vfs_rmdir,
    };
}

/* Self-tests (using mock block device from bcache) */

#include __INC_TEST(sfs)
