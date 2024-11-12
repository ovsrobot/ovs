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

#ifndef DPIF_PLUGIN_H
#define DPIF_PLUGIN_H 1

#ifdef  __cplusplus
extern "C" {
#endif

struct smap;

struct dpif_plugin {
    struct dpif_plugin *next;
    const char *id;

    const void *plugin_class;
    void (*bridge_init)(const struct smap *ovs_other_config);
};

void foreach_plugin_call_bridge_init(const struct smap *ovs_other_config);

struct dpif_plugin *dp_plugin_get(const char *str);

#ifdef  __cplusplus
}
#endif
#endif /* dpif-plugin.h */
