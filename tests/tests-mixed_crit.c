/* SPDX-License-Identifier: MIT */
#include <mazu/sched.h>
#include <mazu/selftest.h>

/* Each test below arms refill callouts on the stack-local hi/lo domains via
 * sched_domain_init; both callouts must be drained on every exit so they
 * cannot fire against the unwound stack frame.
 */

/* Test: MC pair initialization sets criticality fields. */
static i32 test_mc_init_pair(void)
{
    struct sched_domain hi, lo;
    sched_domain_init(&hi, time_ms_to_ticks(70), time_ms_to_ticks(100));
    sched_domain_init(&lo, time_ms_to_ticks(30), time_ms_to_ticks(100));

    sched_mc_init_pair(&hi, &lo);

    i32 rc = 0;
    if (hi.criticality != SCHED_DOMAIN_CRIT_HI)
        rc = 1;
    else if (lo.criticality != SCHED_DOMAIN_CRIT_LO)
        rc = 1;
    else if (hi.mc_peer != &lo || lo.mc_peer != &hi)
        rc = 1;
    else if (hi.mc_state != MC_NORMAL || lo.mc_state != MC_NORMAL)
        rc = 1;

    callout_cancel_sync(&hi.refill_callout);
    callout_cancel_sync(&lo.refill_callout);
    return rc;
}
DEFINE_SELFTEST(mc_init_pair, test_mc_init_pair);

/* Test: escalation triggers when HI overruns budget. */
static i32 test_mc_escalation(void)
{
    struct sched_domain hi, lo;
    sched_domain_init(&hi, time_ms_to_ticks(70), time_ms_to_ticks(100));
    sched_domain_init(&lo, time_ms_to_ticks(30), time_ms_to_ticks(100));
    sched_mc_init_pair(&hi, &lo);

    /* Simulate HI overrun. */
    __atomic_store_n(&hi.consumed_ticks, hi.quantum_ticks + 1,
                     __ATOMIC_RELAXED);
    sched_mc_check_escalation(&hi);

    i32 rc = 0;
    if (hi.mc_state != MC_ESCALATED)
        rc = 1;
    else if (__atomic_load_n(&lo.state, __ATOMIC_ACQUIRE) != DOMAIN_DEPLETED)
        rc = 1;
    else {
        /* Recovery after HI refill. */
        sched_mc_check_recovery(&hi);

        if (hi.mc_state != MC_NORMAL)
            rc = 1;
        else if (__atomic_load_n(&lo.state, __ATOMIC_ACQUIRE) != DOMAIN_ACTIVE)
            rc = 1;
    }

    callout_cancel_sync(&hi.refill_callout);
    callout_cancel_sync(&lo.refill_callout);
    return rc;
}
DEFINE_SELFTEST(mc_escalation, test_mc_escalation);

/* Test: no escalation when HI is within budget. */
static i32 test_mc_no_escalation(void)
{
    struct sched_domain hi, lo;
    sched_domain_init(&hi, time_ms_to_ticks(70), time_ms_to_ticks(100));
    sched_domain_init(&lo, time_ms_to_ticks(30), time_ms_to_ticks(100));
    sched_mc_init_pair(&hi, &lo);

    __atomic_store_n(&hi.consumed_ticks, hi.quantum_ticks / 2,
                     __ATOMIC_RELAXED);
    sched_mc_check_escalation(&hi);

    i32 rc = 0;
    if (hi.mc_state != MC_NORMAL)
        rc = 1;
    else if (__atomic_load_n(&lo.state, __ATOMIC_ACQUIRE) != DOMAIN_ACTIVE)
        rc = 1;

    callout_cancel_sync(&hi.refill_callout);
    callout_cancel_sync(&lo.refill_callout);
    return rc;
}
DEFINE_SELFTEST(mc_no_escalation, test_mc_no_escalation);
