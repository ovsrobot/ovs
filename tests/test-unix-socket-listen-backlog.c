/*
 * Copyright (c) 2010, 2012, 2014 Nicira, Inc.
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
#undef NDEBUG
#include "socket-util.h"
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include "ovstest.h"
#include "util.h"

static void
test_unix_socket_listen_backlog_main(int argc, char *argv[])
{
    const char *servername;
    const char *clientname;
    int serversock;
    int clientsocks[LISTEN_BACKLOG + 1];

    set_program_name(argv[0]);

    if (argc != 3) {
        ovs_fatal(0, "usage: %s SERVERSOCKET CLIENTSOCKET", argv[0]);
    }
    servername = argv[1];
    clientname = argv[2];

    signal(SIGALRM, SIG_DFL);
    alarm(5);

    /* Create a listening socket under name 'serversocket'. */
    serversock = make_unix_socket(SOCK_STREAM, false, servername, NULL);
    if (serversock < 0) {
        ovs_fatal(-serversock, "%s: bind failed", servername);
    }
    if (listen(serversock, 1)) {
        ovs_fatal(errno, "%s: listen failed", servername);
    }

    /* Connect to 'clientname' (which should be the same file, perhaps under a
     * different name). Connect enough times to overflow listen backlog. The
     * last attempt should succeed, even though listen backlog is full and
     * connect() returns EAGAIN (on Linux) or EINPROGRESS (on POSIX). */
    for (int i = 0; i < sizeof(clientsocks) / sizeof(clientsocks[0]); i++) {
        clientsocks[i] = make_unix_socket(SOCK_STREAM, true, NULL, clientname);
        if (clientsocks[i] < 0) {
            ovs_fatal(-clientsocks[i], "%s: connect failed", clientname);
        }
    }

    for (int i = 0; i < sizeof(clientsocks) / sizeof(clientsocks[0]); i++) {
        close(clientsocks[i]);
    }
    close(serversock);
}

OVSTEST_REGISTER("test-unix-socket-listen-backlog",
                 test_unix_socket_listen_backlog_main);
