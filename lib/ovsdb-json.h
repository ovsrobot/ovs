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

#ifndef OVSDB_JSON_H
#define OVSDB_JSON_H

#include <config.h>

#ifdef __cplusplus
extern "C" {
#endif

struct json;

extern struct json OVSDB_JSON_INTEGER_ONE;    /* 1 */
extern struct json OVSDB_JSON_STR_ABORT;      /* "abort" */
extern struct json OVSDB_JSON_STR_ADD_EQ;     /* "+=" */
extern struct json OVSDB_JSON_STR_COMMENT;    /* "comment" */
extern struct json OVSDB_JSON_STR_DELETE;     /* "delete" */
extern struct json OVSDB_JSON_STR_EQ;         /* "=="  */
extern struct json OVSDB_JSON_STR_INSERT;     /* "insert" */
extern struct json OVSDB_JSON_STR_MAP;        /* "map" */
extern struct json OVSDB_JSON_STR_MONID;      /* "monid" */
extern struct json OVSDB_JSON_STR_MUTATE;     /* "mutate" */
extern struct json OVSDB_JSON_STR_NAMED_UUID; /* "named-uuid" */
extern struct json OVSDB_JSON_STR_SELECT;     /* "select" */
extern struct json OVSDB_JSON_STR_SET;        /* "set" */
extern struct json OVSDB_JSON_STR_UPDATE;     /* "update" */
extern struct json OVSDB_JSON_STR_UUID;       /* "uuid" */
extern struct json OVSDB_JSON_STR_WAIT;       /* "wait" */
extern struct json OVSDB_JSON_STR__UUID;      /* "_uuid" */;

#ifdef __cplusplus
}
#endif

#endif
