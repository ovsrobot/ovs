/*
 * Copyright (c) 2024 Red Hat, Inc.
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
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/psample.h>

#include "command-line.h"
#include "dp-packet.h"
#include "util.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/types.h"
#include "openvswitch/uuid.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_psample);

/* -g, --group: Group id filter option */
static uint32_t group_id = 0;
static bool has_filter;

static int psample_family = 0;

OVS_NO_RETURN static void usage(void)
{
    printf("%s: OpenvSwitch psample viewer\n"
"usage: %s [OPTIONS]\n"
"\nOptions:\n"
"  -h, --help               display this help message\n"
"  -t, --group=GROUP        only display events from GROUP group_id\n"
"  -V, --version            display %s version information\n",
          program_name, program_name, program_name);
    exit(EXIT_SUCCESS);
}

struct sample;
static inline void sample_clear(struct sample *sample);
static int parse_psample(struct ofpbuf *, struct sample *sample);
static void psample_set_filter(struct nl_sock *sock);
static void parse_options(int argc, char *argv[]);
static int connect_psample_socket(struct nl_sock **sock);
static void run(struct nl_sock *sock);

int
main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct nl_sock *sock;
    int error;

    parse_options(argc, argv);

    error = connect_psample_socket(&sock);
    if (error) {
        return error;
    }

    run(sock);
}

static void parse_options(int argc, char *argv[])
{
    static const struct option long_options[] = {
        {"group", required_argument, NULL, 'g'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };

    char *short_options_ =
        ovs_cmdl_long_options_to_short_options(long_options);
    char *short_options = xasprintf("+%s", short_options_);

    for (;;) {
        int option;

        option = getopt_long(argc, argv, short_options, long_options, NULL);
        if (option == -1) {
            break;
        }
        switch (option) {
        case 'g':
            {
            char *endptr;

            if (has_filter) {
                ovs_fatal(0, "-g or --group may be specified only once");
            }

            group_id = strtol(optarg, &endptr, 10);
            if (endptr - optarg != strlen(optarg)) {
                ovs_fatal(0, "-g or --group expects a valid decimal"
                          " 32-bit number");
            }

            has_filter = true;
            }
            break;
        case 'h':
            usage();
            break;

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        case '?':
            exit(EXIT_FAILURE);

        default:
            OVS_NOT_REACHED();
        }
    }
    free(short_options_);
    free(short_options);
}

static int connect_psample_socket(struct nl_sock **sock)
{
    unsigned int psample_packet_mcgroup;
    int error;

    error = nl_lookup_genl_family(PSAMPLE_GENL_NAME , &psample_family);
    if (error) {
        VLOG_ERR("PSAMPLE_GENL_NAME not found: %i", error);
    }

    error = nl_lookup_genl_mcgroup(PSAMPLE_GENL_NAME,
                                   PSAMPLE_NL_MCGRP_SAMPLE_NAME,
                                   &psample_packet_mcgroup);
    if (error) {
        VLOG_ERR("psample packet multicast group not found: %i", error);
        return error;
    }

    error = nl_sock_create(NETLINK_GENERIC, sock);
    if (error) {
        VLOG_ERR("cannot create netlink socket: %i ", error);
        return error;
    }

    nl_sock_listen_all_nsid(*sock, true);

    psample_set_filter(*sock);

    error = nl_sock_join_mcgroup(*sock, psample_packet_mcgroup);
    if (error) {
        nl_sock_destroy(*sock);
        *sock = NULL;
        VLOG_ERR("cannot join psample multicast group: %i", error);
        return error;
    }
    return 0;
}

/* Internal representation of a sample. */
struct sample {
    struct dp_packet packet;
    uint32_t group_id;
    uint32_t obs_domain_id;
    uint32_t obs_point_id;
    bool has_cookie;
};

static inline void
sample_clear(struct sample *sample) {
    sample->group_id = 0;
    sample->obs_domain_id = 0;
    sample->obs_point_id = 0;
    sample->has_cookie = false;
    dp_packet_clear(&sample->packet);
}

static int
parse_psample(struct ofpbuf *buf, struct sample *sample) {
    static const struct nl_policy psample_packet_policy[] = {
        [PSAMPLE_ATTR_SAMPLE_GROUP] = { .type = NL_A_U32 },
        [PSAMPLE_ATTR_DATA] = { .type = NL_A_UNSPEC,
                                .optional = true, },
        [PSAMPLE_ATTR_USER_COOKIE] = { .type = NL_A_UNSPEC,
                                       .optional = true },
    };

    struct ofpbuf b = ofpbuf_const_initializer(buf->data, buf->size);
    struct nlmsghdr *nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    struct genlmsghdr *genl = ofpbuf_try_pull(&b, sizeof *genl);
    struct nlattr *attr;
    const uint32_t *cookie;

    struct nlattr *a[ARRAY_SIZE(psample_packet_policy)];
    if (!nlmsg || !genl
        || !nl_policy_parse(&b, 0, psample_packet_policy, a,
                            ARRAY_SIZE(psample_packet_policy))) {
        return EINVAL;
    }

    attr = a[PSAMPLE_ATTR_DATA];
    if (attr) {
        dp_packet_push(&sample->packet, nl_attr_get(attr),
                       nl_attr_get_size(attr));
    }

    sample->group_id = nl_attr_get_u32(a[PSAMPLE_ATTR_SAMPLE_GROUP]);

    attr = a[PSAMPLE_ATTR_USER_COOKIE];
    if (attr && nl_attr_get_size(attr) == 8) {
        cookie = nl_attr_get(attr);
        sample->has_cookie = true;
        sample->obs_domain_id = cookie[0];
        sample->obs_point_id = cookie[1];
    }
    return 0;
}

static int _psample_set_filter(struct nl_sock *sock, uint32_t group,
                               bool valid)
{
        uint64_t stub[512 / 8];
        struct ofpbuf buf;
        int error;

        ofpbuf_use_stub(&buf, stub, sizeof stub);

        nl_msg_put_genlmsghdr(&buf, 0, psample_family, NLM_F_REQUEST,
                              PSAMPLE_CMD_SAMPLE_FILTER_SET, 1);
        if (valid) {
            nl_msg_put_u32(&buf, PSAMPLE_ATTR_SAMPLE_GROUP, group);
        }

        error = nl_sock_send(sock, &buf, false);
        if (error) {
            return error;
        }

        ofpbuf_clear(&buf);
        error = nl_sock_recv(sock, &buf, NULL, false);
        if (!error) {
            struct nlmsghdr *h = ofpbuf_at(&buf, 0, NLMSG_HDRLEN);
            if (h->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *e;
                e = ofpbuf_at(&buf, NLMSG_HDRLEN,
                              NLMSG_ALIGN(sizeof(struct nlmsgerr)));
                if (!e)
                    return EINVAL;
                if (e && e->error < 0)
                    return -e->error;
            }
        } else if (error != EAGAIN) {
            return error;
        }
        return 0;
}

static void psample_set_filter(struct nl_sock *sock)
{
    int error;
    if (has_filter) {
        error = _psample_set_filter(sock, group_id, true);
        if (error) {
            VLOG_WARN("Failed to install in-kernel filter (%s). "
                    "Falling back to userspace filtering.",
                    ovs_strerror(error));
        }
    }
}

static void run(struct nl_sock *sock)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    int error;

    struct sample sample = {};
    dp_packet_init(&sample.packet, 1500);

    for (;;) {
        uint64_t buf_stub[4096 / 8];
        struct ofpbuf buf;

        sample_clear(&sample);

        ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
        error = nl_sock_recv(sock, &buf, NULL, true);

        if (error == ENOBUFS) {
            fprintf(stderr, "[missed events]\n");
            continue;
        } else if (error == EAGAIN) {
            continue;
        } else if (error) {
            VLOG_ERR_RL(&rl, "error reading samples: %i", error);
        }

        error = parse_psample(&buf, &sample);
        if (error)
            VLOG_ERR_RL(&rl, "error parsing samples: %i", error);

        if (!has_filter || sample.group_id == group_id) {
            fprintf(stdout, "group_id=0x%"PRIx32" ",
                sample.group_id);
            if (sample.has_cookie) {
                fprintf(stdout,
                        "obs_domain=0x%"PRIx32",obs_point=0x%"PRIx32" ",
                        sample.obs_domain_id, sample.obs_point_id);
            }
            ofp_print_dp_packet(stdout, &sample.packet);
        }
    }
}

