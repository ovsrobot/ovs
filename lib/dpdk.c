/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "dpdk.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_memzone.h>
#include <rte_version.h>
#ifdef DPDK_PDUMP
#include <rte_pdump.h>
#endif

#include "bitmap.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "netdev-dpdk.h"
#include "netdev-offload-provider.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "smap.h"
#include "svec.h"
#include "unixctl.h"
#include "util.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(dpdk);

static FILE *log_stream = NULL;       /* Stream for DPDK log redirection */

static char *vhost_sock_dir = NULL;   /* Location of vhost-user sockets */
static bool vhost_iommu_enabled = false; /* Status of vHost IOMMU support */
static bool vhost_postcopy_enabled = false; /* Status of vHost POSTCOPY
                                             * support. */
static bool dpdk_initialized = false; /* Indicates successful initialization
                                       * of DPDK. */
static bool per_port_memory = false; /* Status of per port memory support */

static struct ovs_mutex lcore_bitmap_mutex = OVS_MUTEX_INITIALIZER;
static unsigned long *lcore_bitmap OVS_GUARDED_BY(lcore_bitmap_mutex);

static int
process_vhost_flags(char *flag, const char *default_val, int size,
                    const struct smap *ovs_other_config,
                    char **new_val)
{
    const char *val;
    int changed = 0;

    val = smap_get(ovs_other_config, flag);

    /* Process the vhost-sock-dir flag if it is provided, otherwise resort to
     * default value.
     */
    if (val && (strlen(val) <= size)) {
        changed = 1;
        *new_val = xstrdup(val);
        VLOG_INFO("User-provided %s in use: %s", flag, *new_val);
    } else {
        VLOG_INFO("No %s provided - defaulting to %s", flag, default_val);
        *new_val = xstrdup(default_val);
    }

    return changed;
}

static bool
args_contains(const struct svec *args, const char *value)
{
    const char *arg;
    size_t i;

    /* We can't just use 'svec_contains' because args are not sorted. */
    SVEC_FOR_EACH (i, arg, args) {
        if (!strcmp(arg, value)) {
            return true;
        }
    }
    return false;
}

static void
construct_dpdk_lcore_option(const struct smap *ovs_other_config,
                            struct svec *args)
{
    const char *cmask = smap_get(ovs_other_config, "dpdk-lcore-mask");
    struct svec lcores = SVEC_EMPTY_INITIALIZER;
    struct ovs_numa_info_core *core;
    struct ovs_numa_dump *cores;
    int index = 0;

    if (!cmask) {
        return;
    }
    if (args_contains(args, "-c") || args_contains(args, "-l") ||
        args_contains(args, "--lcores")) {
                VLOG_WARN("Ignoring database defined option 'dpdk-lcore-mask' "
                          "due to dpdk-extra config");
        return;
    }

    cores = ovs_numa_dump_cores_with_cmask(cmask);
    FOR_EACH_CORE_ON_DUMP(core, cores) {
        svec_add_nocopy(&lcores, xasprintf("%d@%d", index, core->core_id));
        index++;
    }
    svec_terminate(&lcores);
    ovs_numa_dump_destroy(cores);
    svec_add(args, "--lcores");
    svec_add_nocopy(args, svec_join(&lcores, ",", ""));
    svec_destroy(&lcores);
}

static void
construct_dpdk_options(const struct smap *ovs_other_config, struct svec *args)
{
    struct dpdk_options_map {
        const char *ovs_configuration;
        const char *dpdk_option;
        bool default_enabled;
        const char *default_value;
    } opts[] = {
        {"dpdk-hugepage-dir", "--huge-dir",     false, NULL},
        {"dpdk-socket-limit", "--socket-limit", false, NULL},
    };

    int i;

    /*First, construct from the flat-options (non-mutex)*/
    for (i = 0; i < ARRAY_SIZE(opts); ++i) {
        const char *value = smap_get(ovs_other_config,
                                     opts[i].ovs_configuration);
        if (!value && opts[i].default_enabled) {
            value = opts[i].default_value;
        }

        if (value) {
            if (!args_contains(args, opts[i].dpdk_option)) {
                svec_add(args, opts[i].dpdk_option);
                svec_add(args, value);
            } else {
                VLOG_WARN("Ignoring database defined option '%s' due to "
                          "dpdk-extra config", opts[i].dpdk_option);
            }
        }
    }
}

static char *
construct_dpdk_socket_mem(void)
{
    const char *def_value = "1024";
    int numa, numa_nodes = ovs_numa_get_n_numas();
    struct ds dpdk_socket_mem = DS_EMPTY_INITIALIZER;

    if (numa_nodes == 0 || numa_nodes == OVS_NUMA_UNSPEC) {
        numa_nodes = 1;
    }

    ds_put_cstr(&dpdk_socket_mem, def_value);
    for (numa = 1; numa < numa_nodes; ++numa) {
        ds_put_format(&dpdk_socket_mem, ",%s", def_value);
    }

    return ds_cstr(&dpdk_socket_mem);
}

#define MAX_DPDK_EXCL_OPTS 10

static void
construct_dpdk_mutex_options(const struct smap *ovs_other_config,
                             struct svec *args)
{
    char *default_dpdk_socket_mem = construct_dpdk_socket_mem();

    struct dpdk_exclusive_options_map {
        const char *category;
        const char *ovs_dpdk_options[MAX_DPDK_EXCL_OPTS];
        const char *eal_dpdk_options[MAX_DPDK_EXCL_OPTS];
        const char *default_value;
        int default_option;
    } excl_opts[] = {
        {"memory type",
         {"dpdk-alloc-mem", "dpdk-socket-mem", NULL,},
         {"-m",             "--socket-mem",    NULL,},
         default_dpdk_socket_mem, 1
        },
    };

    int i;
    for (i = 0; i < ARRAY_SIZE(excl_opts); ++i) {
        int found_opts = 0, scan, found_pos = -1;
        const char *found_value;
        struct dpdk_exclusive_options_map *popt = &excl_opts[i];

        for (scan = 0; scan < MAX_DPDK_EXCL_OPTS
                 && popt->ovs_dpdk_options[scan]; ++scan) {
            const char *value = smap_get(ovs_other_config,
                                         popt->ovs_dpdk_options[scan]);
            if (value && strlen(value)) {
                found_opts++;
                found_pos = scan;
                found_value = value;
            }
        }

        if (!found_opts) {
            if (popt->default_option) {
                found_pos = popt->default_option;
                found_value = popt->default_value;
            } else {
                continue;
            }
        }

        if (found_opts > 1) {
            VLOG_ERR("Multiple defined options for %s. Please check your"
                     " database settings and reconfigure if necessary.",
                     popt->category);
        }

        if (!args_contains(args, popt->eal_dpdk_options[found_pos])) {
            svec_add(args, popt->eal_dpdk_options[found_pos]);
            svec_add(args, found_value);
        } else {
            VLOG_WARN("Ignoring database defined option '%s' due to "
                      "dpdk-extra config", popt->eal_dpdk_options[found_pos]);
        }
    }

    free(default_dpdk_socket_mem);
}

static void
construct_dpdk_args(const struct smap *ovs_other_config, struct svec *args)
{
    const char *extra_configuration = smap_get(ovs_other_config, "dpdk-extra");

    if (extra_configuration) {
        svec_parse_words(args, extra_configuration);
    }

    construct_dpdk_lcore_option(ovs_other_config, args);
    construct_dpdk_options(ovs_other_config, args);
    construct_dpdk_mutex_options(ovs_other_config, args);
}

static ssize_t
dpdk_log_write(void *c OVS_UNUSED, const char *buf, size_t size)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);
    static struct vlog_rate_limit dbg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

    switch (rte_log_cur_msg_loglevel()) {
        case RTE_LOG_DEBUG:
            VLOG_DBG_RL(&dbg_rl, "%.*s", (int) size, buf);
            break;
        case RTE_LOG_INFO:
        case RTE_LOG_NOTICE:
            VLOG_INFO_RL(&rl, "%.*s", (int) size, buf);
            break;
        case RTE_LOG_WARNING:
            VLOG_WARN_RL(&rl, "%.*s", (int) size, buf);
            break;
        case RTE_LOG_ERR:
            VLOG_ERR_RL(&rl, "%.*s", (int) size, buf);
            break;
        case RTE_LOG_CRIT:
        case RTE_LOG_ALERT:
        case RTE_LOG_EMERG:
            VLOG_EMER("%.*s", (int) size, buf);
            break;
        default:
            OVS_NOT_REACHED();
    }

    return size;
}

static cookie_io_functions_t dpdk_log_func = {
    .write = dpdk_log_write,
};

static void
dpdk_dump_lcore(struct ds *ds, unsigned lcore)
{
    struct svec cores = SVEC_EMPTY_INITIALIZER;
    rte_cpuset_t cpuset;
    unsigned cpu;

    cpuset = rte_lcore_cpuset(lcore);
    for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &cpuset)) {
            continue;
        }
        svec_add_nocopy(&cores, xasprintf("%u", cpu));
    }
    svec_terminate(&cores);
    ds_put_format(ds, "lcore%u (%s) is running on core %s\n", lcore,
                  rte_eal_lcore_role(lcore) != ROLE_OFF ? "DPDK" : "OVS",
                  svec_join(&cores, ",", ""));
    svec_destroy(&cores);
}

static void
dpdk_dump_lcores(struct unixctl_conn *conn, int argc, const char *argv[],
                 void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    unsigned lcore;

    ovs_mutex_lock(&lcore_bitmap_mutex);
    if (lcore_bitmap == NULL) {
        unixctl_command_reply_error(conn, "DPDK has not been initialised");
        goto out;
    }
    if (argc > 1) {
        if (!str_to_uint(argv[1], 0, &lcore) || lcore >= RTE_MAX_LCORE ||
            !bitmap_is_set(lcore_bitmap, lcore)) {
            unixctl_command_reply_error(conn, "incorrect lcoreid");
            goto out;
        }
        dpdk_dump_lcore(&ds, lcore);
    } else for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        if (!bitmap_is_set(lcore_bitmap, lcore)) {
            continue;
        }
        dpdk_dump_lcore(&ds, lcore);
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
out:
    ovs_mutex_unlock(&lcore_bitmap_mutex);
}

static bool
dpdk_init__(const struct smap *ovs_other_config)
{
    char *sock_dir_subcomponent;
    char **argv = NULL;
    int result;
    bool auto_determine = true;
    int err = 0;
    struct ovs_numa_dump *affinity = NULL;
    struct svec args = SVEC_EMPTY_INITIALIZER;

    log_stream = fopencookie(NULL, "w+", dpdk_log_func);
    if (log_stream == NULL) {
        VLOG_ERR("Can't redirect DPDK log: %s.", ovs_strerror(errno));
    } else {
        setbuf(log_stream, NULL);
        rte_openlog_stream(log_stream);
    }

    if (process_vhost_flags("vhost-sock-dir", ovs_rundir(),
                            NAME_MAX, ovs_other_config,
                            &sock_dir_subcomponent)) {
        struct stat s;
        if (!strstr(sock_dir_subcomponent, "..")) {
            vhost_sock_dir = xasprintf("%s/%s", ovs_rundir(),
                                       sock_dir_subcomponent);

            err = stat(vhost_sock_dir, &s);
            if (err) {
                VLOG_ERR("vhost-user sock directory '%s' does not exist.",
                         vhost_sock_dir);
            }
        } else {
            vhost_sock_dir = xstrdup(ovs_rundir());
            VLOG_ERR("vhost-user sock directory request '%s/%s' has invalid"
                     "characters '..' - using %s instead.",
                     ovs_rundir(), sock_dir_subcomponent, ovs_rundir());
        }
        free(sock_dir_subcomponent);
    } else {
        vhost_sock_dir = sock_dir_subcomponent;
    }

    vhost_iommu_enabled = smap_get_bool(ovs_other_config,
                                        "vhost-iommu-support", false);
    VLOG_INFO("IOMMU support for vhost-user-client %s.",
               vhost_iommu_enabled ? "enabled" : "disabled");

    vhost_postcopy_enabled = smap_get_bool(ovs_other_config,
                                           "vhost-postcopy-support", false);
    if (vhost_postcopy_enabled && memory_locked()) {
        VLOG_WARN("vhost-postcopy-support and mlockall are not compatible.");
        vhost_postcopy_enabled = false;
    }
    VLOG_INFO("POSTCOPY support for vhost-user-client %s.",
              vhost_postcopy_enabled ? "enabled" : "disabled");

    per_port_memory = smap_get_bool(ovs_other_config,
                                    "per-port-memory", false);
    VLOG_INFO("Per port memory for DPDK devices %s.",
              per_port_memory ? "enabled" : "disabled");

    svec_add(&args, ovs_get_program_name());
    construct_dpdk_args(ovs_other_config, &args);

    if (!args_contains(&args, "--legacy-mem")
        && !args_contains(&args, "--socket-limit")) {
        const char *arg;
        size_t i;

        SVEC_FOR_EACH (i, arg, &args) {
            if (!strcmp(arg, "--socket-mem")) {
                break;
            }
        }
        if (i < args.n - 1) {
            svec_add(&args, "--socket-limit");
            svec_add(&args, args.names[i + 1]);
        }
    }

    if (args_contains(&args, "-c") || args_contains(&args, "-l") ||
        args_contains(&args, "--lcores")) {
        auto_determine = false;
    }

    /**
     * NOTE: This is an unsophisticated mechanism for determining the DPDK
     * lcore for the DPDK Master.
     */
    if (auto_determine) {
        const struct ovs_numa_info_core *core;
        int cpu = 0;

        /* Get the main thread affinity */
        affinity = ovs_numa_thread_getaffinity_dump();
        if (affinity) {
            cpu = INT_MAX;
            FOR_EACH_CORE_ON_DUMP (core, affinity) {
                if (cpu > core->core_id) {
                    cpu = core->core_id;
                }
            }
        } else {
            /* User did not set dpdk-lcore-mask and unable to get current
             * thread affintity - default to core #0 */
            VLOG_ERR("Thread getaffinity failed. Using core #0");
        }
        svec_add(&args, "--lcores");
        svec_add_nocopy(&args, xasprintf("0@%d", cpu));
    }

    svec_terminate(&args);

    optind = 1;

    if (VLOG_IS_INFO_ENABLED()) {
        struct ds eal_args = DS_EMPTY_INITIALIZER;
        char *joined_args = svec_join(&args, " ", ".");

        ds_put_format(&eal_args, "EAL ARGS: %s", joined_args);
        VLOG_INFO("%s", ds_cstr_ro(&eal_args));
        ds_destroy(&eal_args);
        free(joined_args);
    }

    /* Copy because 'rte_eal_init' will change the argv, i.e. it will remove
     * some arguments from it. '+1' to copy the terminating NULL.  */
    argv = xmemdup(args.names, (args.n + 1) * sizeof args.names[0]);

    /* Make sure things are initialized ... */
    result = rte_eal_init(args.n, argv);

    free(argv);
    svec_destroy(&args);

    /* Set the main thread affinity back to pre rte_eal_init() value */
    if (affinity) {
        ovs_numa_thread_setaffinity_dump(affinity);
        ovs_numa_dump_destroy(affinity);
    }

    if (result < 0) {
        VLOG_EMER("Unable to initialize DPDK: %s", ovs_strerror(rte_errno));
        return false;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        size_t size;
        char *response = NULL;
        FILE *stream = open_memstream(&response, &size);

        if (stream) {
            rte_memzone_dump(stream);
            fclose(stream);
            if (size) {
                VLOG_DBG("rte_memzone_dump:\n%s", response);
            }
            free(response);
        } else {
            VLOG_DBG("Could not dump memzone. Unable to open memstream: %s.",
                     ovs_strerror(errno));
        }
    }

    ovs_mutex_lock(&lcore_bitmap_mutex);
    lcore_bitmap = bitmap_allocate(RTE_MAX_LCORE);
    /* Mark DPDK threads. */
    for (uint32_t lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        if (rte_eal_lcore_role(lcore) == ROLE_OFF) {
             continue;
        }
        bitmap_set1(lcore_bitmap, lcore);
        dpdk_dump_lcore(&ds, lcore);
        VLOG_INFO("%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }
    unixctl_command_register("dpdk/dump-lcores", "[lcore]", 0, 1,
                             dpdk_dump_lcores, NULL);
    ovs_mutex_unlock(&lcore_bitmap_mutex);

    /* We are called from the main thread here */
    RTE_PER_LCORE(_lcore_id) = NON_PMD_CORE_ID;

#ifdef DPDK_PDUMP
    VLOG_WARN("DPDK pdump support is deprecated and "
              "will be removed in next OVS releases.");
    err = rte_pdump_init();
    if (err) {
        VLOG_INFO("Error initialising DPDK pdump");
    }
#endif

    /* Finally, register the dpdk classes */
    netdev_dpdk_register();
    netdev_register_flow_api_provider(&netdev_offload_dpdk);
    return true;
}

void
dpdk_init(const struct smap *ovs_other_config)
{
    static bool enabled = false;

    if (enabled || !ovs_other_config) {
        return;
    }

    const char *dpdk_init_val = smap_get_def(ovs_other_config, "dpdk-init",
                                             "false");

    bool try_only = !strcasecmp(dpdk_init_val, "try");
    if (!strcasecmp(dpdk_init_val, "true") || try_only) {
        static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once_enable)) {
            VLOG_INFO("Using %s", rte_version());
            VLOG_INFO("DPDK Enabled - initializing...");
            enabled = dpdk_init__(ovs_other_config);
            if (enabled) {
                VLOG_INFO("DPDK Enabled - initialized");
            } else if (!try_only) {
                ovs_abort(rte_errno, "Cannot init EAL");
            }
            ovsthread_once_done(&once_enable);
        } else {
            VLOG_ERR_ONCE("DPDK Initialization Failed.");
        }
    } else {
        VLOG_INFO_ONCE("DPDK Disabled - Use other_config:dpdk-init to enable");
    }
    dpdk_initialized = enabled;
}

const char *
dpdk_get_vhost_sock_dir(void)
{
    return vhost_sock_dir;
}

bool
dpdk_vhost_iommu_enabled(void)
{
    return vhost_iommu_enabled;
}

bool
dpdk_vhost_postcopy_enabled(void)
{
    return vhost_postcopy_enabled;
}

bool
dpdk_per_port_memory(void)
{
    return per_port_memory;
}

bool
dpdk_available(void)
{
    return dpdk_initialized;
}

void
dpdk_init_thread_context(unsigned cpu)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    rte_cpuset_t cpuset;
    unsigned lcore;

    /* NON_PMD_CORE_ID is reserved for use by non pmd threads. */
    ovs_assert(cpu != NON_PMD_CORE_ID);

    ovs_mutex_lock(&lcore_bitmap_mutex);
    if (lcore_bitmap == NULL) {
        lcore = NON_PMD_CORE_ID;
    } else {
        lcore = bitmap_scan(lcore_bitmap, 0, 0, RTE_MAX_LCORE);
        if (lcore == RTE_MAX_LCORE) {
            VLOG_WARN("Reached maximum number of DPDK lcores, core %u will "
                      "have lower performance", cpu);
            lcore = NON_PMD_CORE_ID;
        } else {
            bitmap_set1(lcore_bitmap, lcore);
        }
    }
    ovs_mutex_unlock(&lcore_bitmap_mutex);

    RTE_PER_LCORE(_lcore_id) = lcore;

    if (lcore == NON_PMD_CORE_ID) {
        return;
    }

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    rte_thread_set_affinity(&cpuset);
    dpdk_dump_lcore(&ds, lcore);
    VLOG_INFO("%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

void
dpdk_uninit_thread_context(void)
{
    if (RTE_PER_LCORE(_lcore_id) == NON_PMD_CORE_ID) {
        return;
    }

    ovs_mutex_lock(&lcore_bitmap_mutex);
    bitmap_set0(lcore_bitmap, RTE_PER_LCORE(_lcore_id));
    ovs_mutex_unlock(&lcore_bitmap_mutex);
}

void
print_dpdk_version(void)
{
    puts(rte_version());
}

void
dpdk_status(const struct ovsrec_open_vswitch *cfg)
{
    if (cfg) {
        ovsrec_open_vswitch_set_dpdk_initialized(cfg, dpdk_initialized);
        ovsrec_open_vswitch_set_dpdk_version(cfg, rte_version());
    }
}
