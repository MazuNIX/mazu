/* SPDX-License-Identifier: MIT */
#include <mazu/proc.h>
#include <mazu/selftest.h>

static i32 selftest_elf_load(void)
{
    /* Verify ELF validation rejects garbage. */
    u8 garbage[64] = {0};
    struct byte_view bv = byte_view_new(garbage, sizeof(garbage));
    struct proc *p = proc_alloc();
    assert(p);
    struct result r = proc_load_elf(p, bv);
    assert(r.is_error); /* should fail: bad magic */
    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(elf_load, selftest_elf_load);
