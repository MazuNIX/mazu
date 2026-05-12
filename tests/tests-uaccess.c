/* SPDX-License-Identifier: MIT */
#include <mazu/selftest.h>
#include <mazu/uaccess.h>

static i32 selftest_uaccess_validation(void)
{
    char buf[4] = {0};
    char src[16] = "mazu-uaccess-ok";
    char dst[16] = {0};
    const vaddr_t test_page = USER_DATA_BASE + (128UL * PAGE_SIZE);
    struct proc *p = proc_alloc();
    assert(p);
    assert(
        proc_map_user_page(p, test_page, PT_FLAG_RW | PT_FLAG_USER).is_error ==
        false);

    /* Valid mapped user page copy. */
    assert(copy_to_user(test_page, src, sizeof(src)) == 0);
    assert(copy_from_user(dst, test_page, sizeof(dst)) == 0);
    for (sz i = 0; i < sizeof(src); i++)
        assert(src[i] == dst[i]);

    /* Kernel address must be rejected. */
    assert(copy_to_user(CONFIG_KERN_BASE_VADDR, buf, 4) < 0);
    assert(copy_from_user(buf, CONFIG_KERN_BASE_VADDR, 4) < 0);

    /* Cross-page boundary past user-space limit must be rejected. */
    assert(copy_to_user(USER_STACK_TOP - 8, src, 16) == -(i64) EFAULT);
    assert(copy_from_user(dst, USER_STACK_TOP - 8, 16) == -(i64) EFAULT);
    assert(copy_to_user((ptr) UPTR_MAX - 7, src, 16) == -(i64) EFAULT);
    assert(copy_from_user(dst, (ptr) UPTR_MAX - 7, 16) == -(i64) EFAULT);

    /* Deterministic validation of trap-time fault recovery rewrite. */
    struct trap_frame tf = {0};
    struct pcpu *pc = get_pcpu();
    tf.sepc = 0x1234;
    pc->uaccess_active = true;
    pc->uaccess_faulted = false;
    pc->uaccess_recover_sepc = 0x5678;
    assert(uaccess_handle_page_fault(&tf));
    assert(tf.sepc == 0x5678);
    assert(pc->uaccess_faulted == true);
    pc->uaccess_active = false;
    pc->uaccess_faulted = false;
    pc->uaccess_recover_sepc = 0;

    /* Fault path must recover and allow subsequent valid copies. */
    assert(copy_to_user(test_page, src, sizeof(src)) == 0);
    memset(dst, 0, sizeof(dst));
    assert(copy_from_user(dst, test_page, sizeof(dst)) == 0);
    for (sz i = 0; i < sizeof(src); i++)
        assert(src[i] == dst[i]);

    /* Zero-length is always OK. */
    assert(copy_to_user(0, buf, 0) == 0);
    assert(copy_from_user(buf, 0, 0) == 0);

    proc_free(p);
    return 0;
}
DEFINE_SELFTEST(uaccess_validation, selftest_uaccess_validation);
