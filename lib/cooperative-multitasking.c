/*
 * Copyright (c) 2023 Canonical Ltd.
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

#include "backtrace.h"
#include "cooperative-multitasking-private.h"
#include "cooperative-multitasking.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(cooperative_multitasking);

static struct hmap *cooperative_multitasking_callbacks = NULL;

/* One time initialization for process that wants to make use of cooperative
 * multitasking module.  References to data is stored in 'hmap_container' and
 * will be referenced by all calls to this module.  The ownership of the
 * container itself remains with the caller while the data in the hmap is owned
 * by this module and must be freed with a call to
 * cooperative_multitasking_destroy().
 *
 * The purpose of having the caller own 'hmap_container' is:
 * 1) Allow runtime decision whether to use cooperative multitasking without
 *    having to pass data between loosely connected parts of a program.  This
 *    is useful for the raft code which is consumed by both the ovsdb-server
 *    daemon and the ovsdb-tool CLI utility.
 * 2) Allow inspection of internal data by unit tests. */
void
cooperative_multitasking_init(struct hmap *hmap_container)
{
    cooperative_multitasking_callbacks = hmap_container;
    hmap_init(cooperative_multitasking_callbacks);
}

/* Register callback 'cb' with argument 'arg' to be called when
 * cooperating long running functions yield and 'time_threshold' msec has
 * passed since the last call to the function.
 *
 * It is possible to register the same callback multiple times as long as 'arg'
 * is different for each registration.  It is up to the caller to ensure no
 * unwanted duplicates are registered.
 *
 * The callback is expected to update the timestamp for last run with a call to
 * cooperative_multitasking_update() using the same values for 'cb' and 'arg'.
 */
void
cooperative_multitasking_register(void (*cb)(void *), void *arg,
                                  long long int time_threshold)
{
    if (!cooperative_multitasking_callbacks) {
        return;
    }

    struct cooperative_multitasking_callback *cm_entry;

    cm_entry = xzalloc(sizeof *cm_entry);
    cm_entry->cb = cb;
    cm_entry->arg = arg;
    cm_entry->time_threshold = time_threshold;
    cm_entry->last_run = time_msec();

    hmap_insert(cooperative_multitasking_callbacks,
                &cm_entry->node,
                hash_pointer(
                    cm_entry->arg ? cm_entry->arg : (void *) cm_entry->cb, 0));
}

/* Free any data allocated by calls to cooperative_multitasking_register(). */
void
cooperative_multitasking_destroy(void)
{
    struct cooperative_multitasking_callback *cm_entry;
    HMAP_FOR_EACH_SAFE (cm_entry, node, cooperative_multitasking_callbacks) {
        hmap_remove(cooperative_multitasking_callbacks, &cm_entry->node);
        free(cm_entry);
    }
}

/* Update data for already registered callback identified by 'cb' and 'arg'.
 *
 * Updating the value for 'last_run' is useful if there are multiple entry
 * points to the part serviced by the callback and you want to avoid
 * unnecessary subsequent calls on next call to
 * cooperative_multitasking_yield().
 *
 * Updating the value for 'time_threshold' may be necessary as a consequence of
 * the change in runtime configuration or requirements of the serviced
 * callback.
 *
 * Providing a value of 0 for 'last_run' or 'time_threshold' will result in
 * the respective stored value left untouched. */
void
cooperative_multitasking_update(void (*cb)(void *), void *arg,
                                long long int last_run,
                                long long int time_threshold)
{
    if (!cooperative_multitasking_callbacks) {
        return;
    }

    struct cooperative_multitasking_callback *cm_entry;

    HMAP_FOR_EACH_WITH_HASH (cm_entry, node,
                             hash_pointer(arg ? arg : (void *) cb, 0),
                             cooperative_multitasking_callbacks)
    {
        if (cm_entry->cb == cb && cm_entry->arg == arg) {
            if (last_run) {
                cm_entry->last_run = last_run;
            }

            if (time_threshold) {
                cm_entry->time_threshold = time_threshold;
            }
            return;
        }
    }
}

static void
cooperative_multitasking_yield_at__(const char *source_location)
{
    long long int now = time_msec();
    struct cooperative_multitasking_callback *cm_entry;

    HMAP_FOR_EACH (cm_entry, node, cooperative_multitasking_callbacks) {
        long long int elapsed = now - cm_entry->last_run;

        if (elapsed >= cm_entry->time_threshold) {
            VLOG_DBG("yield called from %s: "
                     "%lld: %lld >= %lld, executing %p(%p)",
                     source_location, now, elapsed, cm_entry->time_threshold,
                     cm_entry->cb, cm_entry->arg);
            (*cm_entry->cb)(cm_entry->arg);
            if (elapsed - cm_entry->time_threshold >
                cm_entry->time_threshold / 8)
            {
                VLOG_WARN("yield threshold overrun with %lld msec, enable "
                          "debug logging for more details.",
                          elapsed - cm_entry->time_threshold);
                if (VLOG_IS_DBG_ENABLED()) {
                    /* log_backtrace() logs at ERROR level but we only want to
                     * log a backtrace when DEBUG is enabled */
                    log_backtrace();
                }
            }
        }
    }
}

/* Iterate over registered callbacks and execute callbacks as demanded by the
 * recorded time threshold. */
void
cooperative_multitasking_yield_at(const char *source_location)
{
    static bool yield_in_progress = false;

    if (!cooperative_multitasking_callbacks) {
        return;
    }

    if (yield_in_progress) {
        VLOG_ERR_ONCE("nested yield avoided, this is a bug! "
                      "enable debug logging for more details.");
        if (VLOG_IS_DBG_ENABLED()) {
            VLOG_DBG("nested yield, called from %s", source_location);
            log_backtrace();
        }
        return;
    }
    yield_in_progress = true;

    cooperative_multitasking_yield_at__(source_location);

    yield_in_progress = false;
}
