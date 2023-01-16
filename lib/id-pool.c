/*
 * Copyright (c) 2014 Nicira, Inc.
 * Copyright (c) 2014 Netronome.
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
#include "id-pool.h"
#include "bitmap.h"

#define ID_POOL_BASE_ALLOC 64

struct id_pool {
    unsigned long *bitmap;
    uint32_t bitmap_size;  /* Current highest offset the bitmap can hold */
    uint32_t base;         /* IDs in the range of [base, base + n_ids). */
    uint32_t n_ids;        /* Total number of ids in the pool. */
};

static void id_pool_init(struct id_pool *pool,
                         uint32_t base, uint32_t n_ids);
static void id_pool_uninit(struct id_pool *pool);

struct id_pool *
id_pool_create(uint32_t base, uint32_t n_ids)
{
    struct id_pool *pool;

    pool = xmalloc(sizeof *pool);
    id_pool_init(pool, base, n_ids);

    return pool;
}

void
id_pool_destroy(struct id_pool *pool)
{
    if (pool) {
        id_pool_uninit(pool);
        free(pool);
    }
}

static void
id_pool_init(struct id_pool *pool, uint32_t base, uint32_t n_ids)
{
    pool->base = base;
    pool->n_ids = n_ids;
    pool->bitmap_size = MIN(n_ids, ID_POOL_BASE_ALLOC);
    pool->bitmap = bitmap_allocate(pool->bitmap_size);
}

static void
id_pool_uninit(struct id_pool *pool)
{
    free(pool->bitmap);
    pool->bitmap = NULL;
}

static bool
id_pool_expand(struct id_pool *pool, uint32_t target)
{
    if (target >= pool->n_ids) {
        return false;
    }

    uint32_t new_bitmap_size = MAX(pool->bitmap_size * 2, target);
    new_bitmap_size = MIN(new_bitmap_size, pool->n_ids);
    unsigned long *new_bitmap = bitmap_allocate(new_bitmap_size);

    memcpy(new_bitmap, pool->bitmap, bitmap_n_bytes(pool->bitmap_size));

    id_pool_uninit(pool);
    pool->bitmap = new_bitmap;
    pool->bitmap_size = new_bitmap_size;
    return true;
}

static bool
id_pool_add__(struct id_pool *pool, uint32_t offset)
{
    if (offset >= pool->n_ids) {
        return false;
    }

    if (offset >= pool->bitmap_size && !id_pool_expand(pool, offset)) {
        return false;
    }

    bitmap_set1(pool->bitmap, offset);
    return true;
}

void
id_pool_add(struct id_pool *pool, uint32_t id)
{
    if (id < pool->base) {
        return;
    }

    id_pool_add__(pool, id - pool->base);
}

bool
id_pool_alloc_id(struct id_pool *pool, uint32_t *id_)
{
    size_t offset;

    if (pool->n_ids == 0) {
        return false;
    }

    offset = bitmap_scan(pool->bitmap, 0, 0, pool->bitmap_size);
    if (!id_pool_add__(pool, offset)) {
        return false;
    }

    *id_ = offset + pool->base;
    return true;
}

void
id_pool_free_id(struct id_pool *pool, uint32_t id)
{
    bitmap_set0(pool->bitmap, id - pool->base);
}
