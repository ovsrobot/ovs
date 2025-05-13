/*
 * Copyright (c) 2025 NVIDIA Corporation.
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
#include "ovsdb-json.h"

struct json OVSDB_JSON_INTEGER_ONE = JSON_STATIC_INT_INITIALIZER(1);
struct json OVSDB_JSON_STR_ABORT   = JSON_STATIC_STRING_INITIALIZER("abort");
struct json OVSDB_JSON_STR_ADD_EQ  = JSON_STATIC_STRING_INITIALIZER("+=");
struct json OVSDB_JSON_STR_COMMENT = JSON_STATIC_STRING_INITIALIZER("comment");
struct json OVSDB_JSON_STR_DELETE  = JSON_STATIC_STRING_INITIALIZER("delete");
struct json OVSDB_JSON_STR_EQ      = JSON_STATIC_STRING_INITIALIZER("==" );
struct json OVSDB_JSON_STR_INSERT  = JSON_STATIC_STRING_INITIALIZER("insert");
struct json OVSDB_JSON_STR_MAP     = JSON_STATIC_STRING_INITIALIZER("map");
struct json OVSDB_JSON_STR_MONID   = JSON_STATIC_STRING_INITIALIZER("monid");
struct json OVSDB_JSON_STR_MUTATE  = JSON_STATIC_STRING_INITIALIZER("mutate");
struct json OVSDB_JSON_STR_SELECT  = JSON_STATIC_STRING_INITIALIZER("select");
struct json OVSDB_JSON_STR_SET     = JSON_STATIC_STRING_INITIALIZER("set");
struct json OVSDB_JSON_STR_UPDATE  = JSON_STATIC_STRING_INITIALIZER("update");
struct json OVSDB_JSON_STR_UUID    = JSON_STATIC_STRING_INITIALIZER("uuid");
struct json OVSDB_JSON_STR_WAIT    = JSON_STATIC_STRING_INITIALIZER("wait");
struct json OVSDB_JSON_STR__UUID   = JSON_STATIC_STRING_INITIALIZER("_uuid");
struct json OVSDB_JSON_STR_NAMED_UUID =
    JSON_STATIC_STRING_INITIALIZER("named-uuid");



