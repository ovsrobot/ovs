
#include <config.h>
#include "dpif-netdev-lookup.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev_lookup);

/* Actual list of implementations goes here */
static struct dpcls_subtable_lookup_info_t subtable_lookups[] = {
    /* Lowest priority - the auto testing implementation will not be used
     * by default, it must be enabled by user */
    { .prio = 0,
      .probe = dpcls_subtable_autovalidator_probe,
      .name = "autovalidator", },

    /* Second lowest priority - the default scalar implementation */
    { .prio = 1,
      .probe = dpcls_subtable_generic_probe,
      .name = "generic", },
};

int32_t
dpcls_subtable_lookup_info_get(struct dpcls_subtable_lookup_info_t **out_ptr)
{
    if (out_ptr == NULL) {
        return -1;
    }

    *out_ptr = subtable_lookups;
    return ARRAY_SIZE(subtable_lookups);
}

/* sets the priority of the lookup function with "name" */
int32_t
dpcls_subtable_set_prio(const char *name, uint8_t priority)
{
    for (int i = 0; i < ARRAY_SIZE(subtable_lookups); i++) {
        if (strcmp(name, subtable_lookups[i].name) == 0) {
                subtable_lookups[i].prio = priority;
                VLOG_INFO("Subtable function '%s' set priority to %d\n",
                         name, priority);
                return 0;
        }
    }
    VLOG_WARN("Subtable function '%s' not found, failed to set priority\n",
              name);
    return -EINVAL;
}

dpcls_subtable_lookup_func
dpcls_subtable_get_best_impl(uint32_t u0_bit_count, uint32_t u1_bit_count)
{
    /* Iter over each subtable impl, and get highest priority one. */
    int32_t prio = -1;
    const char *name = 0;
    dpcls_subtable_lookup_func best_func = NULL;

    for (int i = 0; i < ARRAY_SIZE(subtable_lookups); i++) {
        int32_t probed_prio = subtable_lookups[i].prio;
        if (probed_prio > prio) {
            dpcls_subtable_lookup_func probed_func;
            probed_func = subtable_lookups[i].probe(u0_bit_count,
                                    u1_bit_count);
            if (probed_func) {
                best_func = probed_func;
                prio = probed_prio;
                name = subtable_lookups[i].name;
            }
        }
    }

    VLOG_DBG("Subtable lookup function '%s' with units (%d,%d), priority %d\n",
             name, u0_bit_count, u1_bit_count, prio);

    /* Programming error - we must always return a valid func ptr */
    ovs_assert(best_func != NULL);

    return best_func;
}
