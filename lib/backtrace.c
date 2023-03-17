/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013 Nicira, Inc.
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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include "backtrace.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(backtrace);

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
void
backtrace_capture(struct backtrace *b)
{
    b->n_frames = backtrace(b->frames, BACKTRACE_MAX_FRAMES);
}

void
backtrace_format(const struct backtrace *bt, struct ds *ds)
{
    if (bt->n_frames) {
        char **symbols = backtrace_symbols(bt->frames, bt->n_frames);
        if (!symbols) {
            return;
        }

        for (int i = 0; i < bt->n_frames; i++) {
            ds_put_format(ds, "%s\n", symbols[i]);
        }

        free(symbols);
    }
}

#else
void
backtrace_capture(struct backtrace *backtrace)
{
    backtrace->n_frames = 0;
}

void
backtrace_format(const struct backtrace *bt OVS_UNUSED, struct ds *ds)
{
    ds_put_cstr(ds, "backtrace() is not supported!\n");
}
#endif

void
log_backtrace_at(const char *msg, const char *where)
{
    struct backtrace b;
    struct ds ds = DS_EMPTY_INITIALIZER;

    backtrace_capture(&b);
    if (msg) {
        ds_put_format(&ds, "%s ", msg);
    }

    ds_put_cstr(&ds, where);
    ds_put_cstr(&ds, " backtrace:\n");
    backtrace_format(&b, &ds);
    VLOG_ERR("%s", ds_cstr_ro(&ds));

    ds_destroy(&ds);
}
