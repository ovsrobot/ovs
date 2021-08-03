/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2016, 2017 Nicira, Inc.
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

#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "parallel-hmap.h"
#include "parallel-json.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_parallel_json);


/* Second level json object merge.
 * The second level in ftxn is a (s)hash of rows keyed by UUID.
 * They are unique, so we can brute force add them to the
 * destination (s)hash.
 */

static void
merge_ovsdb_rows(struct json *dest, struct json *inc)
{
    ovs_assert(dest->type == JSON_OBJECT);
    ovs_assert(dest->type == JSON_OBJECT);
    if (dest->object->map.mask == inc->object->map.mask) {
        fast_hmap_merge(&dest->object->map, &inc->object->map);
    } else {
        struct shash_node *node, *next;
        SHASH_FOR_EACH_SAFE (node, next, inc->object) {
            shash_add_once(dest->object, node->name, node->data);
            /* shash delete frees the name and the node struct */
            shash_delete(inc->object, node);
        }
    }
    /* The inc object should be empty at this point */
    json_destroy(inc);
}
/* First level merge.
 * The first level in ftxn is a (s)hash of tables with rows at
 * level 2.
 * If the destination table entry exists, we merge rows. Otherwise,
 * we create it by moving the new entry and its rows in place.
 */

void
parallel_json_merge_tables(struct json **dest, struct json *inc)
{
    struct json *target;
    struct shash_node *node, *next;

    if (!inc) {
        return;
    }

    if (!*dest) {
        *dest = inc;
        return;
    }

    SHASH_FOR_EACH_SAFE (node, next, inc->object) {
        target = shash_find_data((*dest)->object, node->name);
        if (target) {
            /* Target exists, merge rows. Merge will destroy
             * the remnant json rows object in the second argument.
             */
            merge_ovsdb_rows(target, (struct json *) node->data);
        } else {
            /* Target does not exists, move rows.
             * The json object is now part of dest.
             */
            shash_add((*dest)->object, node->name, node->data);
        }
        /* Delete the remnant tables object */
        shash_delete(inc->object, node);
    }
    /* Destroy remnant inc (should be empty at this point). */
    json_destroy(inc);
}
