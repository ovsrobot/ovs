/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

/* XXX: Use libtool ltdl instead of dlopen ? */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <config.h>
#include "dpif-plugin.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_plugin);

static void *BODY;      /* cached handle dlopen(NULL) */
static struct dpif_plugin *dpif_plugin_list;

void foreach_plugin_call_bridge_init(const struct smap *ovs_other_config) {
    struct dpif_plugin *p;

    for (p = dpif_plugin_list; p; p = p->next) {
        if (p->bridge_init) {
            p->bridge_init(ovs_other_config);
        }
    }
}

static struct dpif_plugin *
any_plugin_get(const char *prefix, const char *str)
{
    struct dpif_plugin *p;
    char buf[256];
    void *dlh;

    for (p = dpif_plugin_list; p; p = p->next) {
        if (strcmp(p->id, str) == 0) {
            return p;
        }
    }

    snprintf(buf, sizeof(buf), "%s-%s.so", prefix, str);
    dlh = dlopen(buf, RTLD_LAZY);
    if (!dlh) {
        /* look in current binary, only open once */
        dlh = BODY;
        if (dlh == NULL) {
            dlh = BODY = dlopen(NULL, RTLD_LAZY);
            if (dlh == NULL)
                goto noexist;
        }
    }

    VLOG_INFO("Loaded plugin '%s-%s'", prefix, str);
    dlerror();    /* Clear any existing error */
    snprintf(buf, sizeof(buf), "%s_%s_plugin", prefix, str);
    p = dlsym(dlh, buf);
    if (p == NULL) {
        VLOG_INFO("Cannot find symbol '%s_%s_plugin'", prefix, str);
        goto noexist;
    }

    p->next = dpif_plugin_list;
    p->id = strdup(str);
    dpif_plugin_list = p;
    return p;

noexist:
    return NULL;
}

struct dpif_plugin *
dp_plugin_get(const char *str)
{
    return any_plugin_get("dpif", str);
}
