/*
 * Copyright (c) 2020, Red Hat, Inc.
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
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "dirs.h"
#include "ovs-atomic.h"
#include "util.h"
#include "stream-provider.h"
#include "stream.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(stream_replay);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 25);

/* Stream replay. */

static struct ovs_mutex replay_mutex = OVS_MUTEX_INITIALIZER;
static int replay_seqno OVS_GUARDED_BY(replay_mutex) = 0;
static atomic_int replay_state = ATOMIC_VAR_INIT(STREAM_REPLAY_NONE);

void
stream_replay_set_state(enum stream_replay_state state)
{
    atomic_store_relaxed(&replay_state, state);
}

enum stream_replay_state
stream_replay_get_state(void)
{
    int state;

    atomic_read_relaxed(&replay_state, &state);
    return state;
}

static char *
replay_file_name(const char *name, int seqno)
{
    char *local_name = xstrdup(name);
    char *filename, *p, *c;
    bool skip = false;

    /* Replace all the numbers and special symbols with single underscore.
     * Numbers might be PIDs or port numbers that could change between record
     * and replay phases, special symbols might be not good as a filename.
     * We have a unique seuqence number as part of the name, so we don't care
     * keeping too much information. */
    for (c = p = local_name; *p; p++) {
         if (!isalpha((unsigned char) *p)) {
             if (!skip) {
                *c++ = '_';
                skip = true;
             }
         } else {
             *c++ = *p;
             skip = false;
         }
    }
    if (skip) {
        c--;
    }
    *c = '\0';
    filename = xasprintf("replay_%s_%d", local_name, seqno);
    VLOG_DBG("Constructing replay filename: '%s' --> '%s' --> '%s'.",
             name, local_name, filename);
    free(local_name);

    return filename;
}

/* In write mode creates a new replay file to write stream replay.
 * In read mode opens an existing replay file. */
static int
replay_file_open(const char *name, FILE **f, int *seqno)
    OVS_REQUIRES(replay_mutex)
{
    char *file_path, *filename;
    int state = stream_replay_get_state();

    ovs_assert(state != STREAM_REPLAY_NONE);

    filename = replay_file_name(name, replay_seqno);
    file_path = abs_file_name(ovs_rundir(), filename);
    free(filename);

    *f = fopen(file_path, state == STREAM_REPLAY_WRITE ? "wb" : "rb");
    if (!*f) {
        VLOG_ERR("%s: fopen failed: %s", file_path, ovs_strerror(errno));
        free(file_path);
        return errno;
    }
    free(file_path);

    if (state == STREAM_REPLAY_READ
        && fread(seqno, sizeof *seqno, 1, *f) != 1) {
        VLOG_INFO("%s: failed to read seqno: stream might be empty.", name);
        *seqno = INT_MAX;
    }
    replay_seqno++;  /* New file opened. */
    return 0;
}

static int
replay_write(FILE *f, const void *buffer, int n, bool is_read)
{
    int state = stream_replay_get_state();
    int seqno_to_write;
    int retval = 0;

    if (OVS_LIKELY(state != STREAM_REPLAY_WRITE)) {
        return 0;
    }

    ovs_mutex_lock(&replay_mutex);

    seqno_to_write = is_read ? replay_seqno : -replay_seqno;
    if (fwrite(&seqno_to_write, sizeof seqno_to_write, 1, f) != 1) {
        VLOG_ERR_RL(&rl, "Failed to write seqno.");
        retval = -1;
        goto out;
    }
    if (fwrite(&n, sizeof n, 1, f) != 1) {
        VLOG_ERR_RL(&rl, "Failed to write length.");
        retval = -1;
        goto out;
    }
    if (n > 0 && is_read && fwrite(buffer, 1, n, f) != n) {
        VLOG_ERR_RL(&rl, "Failed to write data.");
        retval = -1;
    }
out:
    replay_seqno++; /* Write completed. */
    ovs_mutex_unlock(&replay_mutex);
    return retval;
}

static int
replay_read(FILE *f, void *buffer, int buffer_size,
            int *len, int *seqno, bool is_read)
    OVS_REQUIRES(replay_mutex)
{
    int retval = EINVAL;

    if (fread(len, sizeof *len, 1, f) != 1
        || (is_read && *len > buffer_size)) {
        VLOG_ERR("Failed to read replay length.");
        goto out;
    }

    if (*len > 0 && is_read && fread(buffer, 1, *len, f) != *len) {
        VLOG_ERR("Failed to read replay buffer.");
        goto out;
    }

    if (fread(seqno, sizeof *seqno, 1, f) != 1) {
        *seqno = INT_MAX;  /* Most likely EOF. */
        if (ferror(f)) {
            VLOG_INFO("Failed to read replay seqno.");
            goto out;
        }
    }

    retval = 0;
out:
    replay_seqno++;  /* Read completed. */
    return retval;
}


/* Active replay stream. */

struct stream_replay
{
    struct stream stream;
    FILE *f;
    int seqno;
};

const struct stream_class replay_stream_class;

static inline bool
seqno_is_read(int seqno)
{
    return seqno >= 0;
}

static inline int
normalized_seqno(int seqno)
{
    return seqno >= 0 ? seqno : -seqno;
}


/* Creates a new stream named 'name' that will emulate sending and receiving
 * data using replay file and stores a pointer to the stream in '*streamp'.
 *
 * Takes ownership of 'name'.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
static int
new_replay_stream(char *name, struct stream **streamp)
    OVS_REQUIRES(replay_mutex)
{
    struct stream_replay *s;
    int seqno = 0, error;
    FILE *f;

    error = replay_file_open(name, &f, &seqno);
    if (error) {
        VLOG_ERR("%s: failed to open stream.", name);
        return error;
    }

    s = xmalloc(sizeof *s);
    stream_init(&s->stream, &replay_stream_class, 0, name);
    s->f = f;
    s->seqno = seqno;
    *streamp = &s->stream;
    return 0;
}

static struct stream_replay *
stream_replay_cast(struct stream *stream)
{
    stream_assert_class(stream, &replay_stream_class);
    return CONTAINER_OF(stream, struct stream_replay, stream);
}

void
stream_replay_open_wfd(struct stream *s)
{
    FILE *f;
    int state = stream_replay_get_state();

    if (OVS_LIKELY(state != STREAM_REPLAY_WRITE)) {
        return;
    }

    ovs_mutex_lock(&replay_mutex);
    if (!replay_file_open(s->name, &f, NULL)) {
        s->replay_wfd = f;
    }
    ovs_mutex_unlock(&replay_mutex);
}

void
stream_replay_write(struct stream *s, const void *buffer, int n, bool is_read)
{
    int state = stream_replay_get_state();

    if (OVS_LIKELY(state != STREAM_REPLAY_WRITE)) {
        return;
    }
    if (replay_write(s->replay_wfd, buffer, n, is_read)) {
        VLOG_ERR("%s: failed to write buffer.", s->name);
    }
}

void
stream_replay_close_wfd(struct stream *s)
{
    if (s->replay_wfd) {
        fclose(s->replay_wfd);
    }
}

static int
replay_open(const char *name, char *suffix OVS_UNUSED, struct stream **streamp,
          uint8_t dscp OVS_UNUSED)
{
    int retval;

    ovs_mutex_lock(&replay_mutex);
    retval = new_replay_stream(xstrdup(name), streamp);
    ovs_mutex_unlock(&replay_mutex);

    return retval;
}

static void
replay_close(struct stream *stream)
{
    struct stream_replay *s = stream_replay_cast(stream);
    fclose(s->f);
    free(s);
}

static ssize_t
replay_recv(struct stream *stream, void *buffer, size_t n)
{
    struct stream_replay *s = stream_replay_cast(stream);
    int norm_seqno = normalized_seqno(s->seqno);
    int error, len;

    ovs_mutex_lock(&replay_mutex);
    ovs_assert(norm_seqno >= replay_seqno);

    if (norm_seqno != replay_seqno || !seqno_is_read(s->seqno)) {
        error = EAGAIN;
        goto unlock;
    }

    error = replay_read(s->f, buffer, n, &len, &s->seqno, true);
    if (error) {
        VLOG_ERR("%s: failed to read from replay file.", stream->name);
        goto unlock;
    }

unlock:
    ovs_mutex_unlock(&replay_mutex);
    return error ? -error : len;
}

static ssize_t
replay_send(struct stream *stream OVS_UNUSED, const void *buffer OVS_UNUSED,
            size_t n)
{
    struct stream_replay *s = stream_replay_cast(stream);
    int norm_seqno = normalized_seqno(s->seqno);
    int error, len;

    ovs_mutex_lock(&replay_mutex);
    ovs_assert(norm_seqno >= replay_seqno);

    if (norm_seqno != replay_seqno || seqno_is_read(s->seqno)) {
        error = EAGAIN;
        goto unlock;
    }

    error = replay_read(s->f, NULL, 0, &len, &s->seqno, false);
    if (error) {
        VLOG_ERR("%s: failed to read from replay file.", stream->name);
        goto unlock;
    }
    ovs_assert(len < 0 || len <= n);

unlock:
    ovs_mutex_unlock(&replay_mutex);
    return error ? -error : len;
}

static void
replay_wait(struct stream *stream, enum stream_wait_type wait)
{
    struct stream_replay *s = stream_replay_cast(stream);
    switch (wait) {
    case STREAM_CONNECT:
        /* Connect does nothing and always avaialable. */
        poll_immediate_wake();
        break;

    case STREAM_SEND:
        if (s->seqno != INT_MAX && !seqno_is_read(s->seqno)) {
            /* Stream waits for write. */
            poll_immediate_wake();
        }
        break;

    case STREAM_RECV:
        if (s->seqno != INT_MAX && seqno_is_read(s->seqno)) {
            /* We still have something to read. */
            poll_immediate_wake();
        }
        break;

    default:
        OVS_NOT_REACHED();
    }
}

const struct stream_class replay_stream_class = {
    "replay",                   /* name */
    false,                      /* needs_probes */
    replay_open,                /* open */
    replay_close,               /* close */
    NULL,                       /* connect */
    replay_recv,                /* recv */
    replay_send,                /* send */
    NULL,                       /* run */
    NULL,                       /* run_wait */
    replay_wait,                /* wait */
};

/* Passive file descriptor stream. */

struct replay_pstream
{
    struct pstream pstream;
    FILE *f;
    int seqno;
};

const struct pstream_class preplay_pstream_class;

static struct replay_pstream *
replay_pstream_cast(struct pstream *pstream)
{
    pstream_assert_class(pstream, &preplay_pstream_class);
    return CONTAINER_OF(pstream, struct replay_pstream, pstream);
}

/* Creates a new pstream named 'name' that will accept new replay connections
 * reading them from the replay file and stores a pointer to the stream in
 * '*pstreamp'.
 *
 * Takes ownership of 'name'.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
static int
preplay_listen(const char *name, char *suffix OVS_UNUSED,
               struct pstream **pstreamp, uint8_t dscp OVS_UNUSED)
{
    int seqno = 0, error;
    FILE *f;

    ovs_mutex_lock(&replay_mutex);
    error = replay_file_open(name, &f, &seqno);
    ovs_mutex_unlock(&replay_mutex);
    if (error) {
        VLOG_ERR("%s: failed to open pstream.", name);
        return error;
    }

    struct replay_pstream *ps = xmalloc(sizeof *ps);
    pstream_init(&ps->pstream, &preplay_pstream_class, xstrdup(name));
    ps->f = f;
    ps->seqno = seqno;
    *pstreamp = &ps->pstream;
    return 0;
}

void
pstream_replay_open_wfd(struct pstream *ps)
{
    FILE *f;
    int state = stream_replay_get_state();

    if (OVS_LIKELY(state != STREAM_REPLAY_WRITE)) {
        return;
    }

    ovs_mutex_lock(&replay_mutex);
    if (!replay_file_open(ps->name, &f, NULL)) {
        ps->replay_wfd = f;
    }
    ovs_mutex_unlock(&replay_mutex);
}


void
pstream_replay_write_accept(struct pstream *ps, const struct stream *s)
{
    int state = stream_replay_get_state();
    int len;

    if (OVS_LIKELY(state != STREAM_REPLAY_WRITE)) {
        return;
    }

    len = strlen(s->name);
    if (replay_write(ps->replay_wfd, s->name, len, true)) {
        VLOG_ERR("%s: failed to write accept name: %s", ps->name, s->name);
    }
}

void
pstream_replay_close_wfd(struct pstream *ps)
{
    if (ps->replay_wfd) {
        fclose(ps->replay_wfd);
    }
}


static void
preplay_close(struct pstream *pstream)
{
    struct replay_pstream *ps = replay_pstream_cast(pstream);

    fclose(ps->f);
    free(ps);
}

#define MAX_NAME_LEN 65536

static int
preplay_accept(struct pstream *pstream, struct stream **new_streamp)
{
    struct replay_pstream *ps = replay_pstream_cast(pstream);
    int norm_seqno = normalized_seqno(ps->seqno);
    int retval, len;
    char name[MAX_NAME_LEN];

    ovs_mutex_lock(&replay_mutex);
    ovs_assert(norm_seqno >= replay_seqno);

    if (norm_seqno != replay_seqno || !seqno_is_read(ps->seqno)) {
        retval = EAGAIN;
        goto unlock;
    }

    retval = replay_read(ps->f, name, MAX_NAME_LEN - 1,
                         &len, &ps->seqno, true);
    if (retval) {
        VLOG_ERR("%s: failed to read from replay file.", pstream->name);
        goto unlock;
    }

    if (len > 0) {
        name[len] = 0;
        retval = new_replay_stream(xstrdup(name), new_streamp);
    } else {
        retval = len;
    }
unlock:
    ovs_mutex_unlock(&replay_mutex);
    return retval;
}

static void
preplay_wait(struct pstream *pstream)
{
    struct replay_pstream *ps = replay_pstream_cast(pstream);

    if (ps->seqno != INT_MAX) {
        /* Replay always has somthing to say. */
        poll_immediate_wake();
    }
}

const struct pstream_class preplay_pstream_class = {
    "preplay",
    false,
    preplay_listen,
    preplay_close,
    preplay_accept,
    preplay_wait,
};
