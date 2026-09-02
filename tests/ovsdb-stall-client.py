# Copyright (c) 2026 Open vSwitch project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Seeds a database, then monitors it from a peer that does not keep up.

Used by the ovsdb-server checks that a peer which stops taking data does not
drive the poll loop.  Two connections are made: the first inserts enough rows
that one monitor reply cannot fit in the socket buffers, the second issues the
monitor and then reads at --throttle bytes a second, so the reply stands in
ovsdb-server's own queue.

--throttle 0, the default and what those checks use, never reads at all.  A
positive rate arms the same case whenever it is slow enough that the queue
does not move within a probe interval, which is a property of the receive
buffer as much as the rate: a receiver defers window updates until a
worthwhile part of its buffer is free, so the queue stalls for roughly
buffer/rate seconds.  The socket is left with whatever the kernel gives it,
as a real peer would be.

Prints READY once the monitor request has been sent.
"""

import argparse
import json
import socket
import ssl
import sys
import time

TLS = None  # (private key, certificate, CA certificate), or None for plain tcp


def connect(target):
    host, port = target.rsplit(':', 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, int(port)))
    if TLS:
        key, cert, ca = TLS
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(cert, key)
        ctx.load_verify_locations(ca)
        # No cert for "127.0.0.1"; ovsdb authenticates by CA, not name.
        ctx.check_hostname = False
        sock = ctx.wrap_socket(sock)
    return sock


def transact(sock, ops):
    sock.sendall(json.dumps({"method": "transact",
                             "params": ops, "id": 0}).encode())
    buf = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            sys.exit("ovsdb-stall-client: server closed while seeding")
        buf += chunk
        try:
            return json.loads(buf.decode())
        except ValueError:
            continue


def drain(sock, rate):
    """Reads 'rate' bytes a second from 'sock', forever."""
    slice_ = max(1, rate // 10)
    while True:
        deadline = time.time() + 0.1
        got = 0
        # recv() returns what is buffered, which is less than asked for
        # whenever the receive buffer is small.  Keep going until the slice
        # is filled, or the window is up, so the rate is the one requested.
        while got < slice_:
            try:
                data = sock.recv(slice_ - got)
            except OSError:
                return
            if not data:
                return
            got += len(data)
            if time.time() >= deadline:
                break
        delay = deadline - time.time()
        if delay > 0:
            time.sleep(delay)


def main(argv):
    global TLS
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", help="[HOST:]PORT of the ovsdb-server")
    parser.add_argument("rows", type=int, help="rows to seed")
    parser.add_argument("blobsize", type=int, help="bytes per seeded row")
    parser.add_argument("--throttle", type=int, default=0, metavar="BYTES",
                        help="read this many bytes a second (0: never read)")
    parser.add_argument("--tls", nargs=3, default=None,
                        metavar=("PRIVKEY", "CERT", "CACERT"),
                        help="speak TLS, with these PEM files")
    args = parser.parse_args(argv[1:])
    target, rows, blob = args.target, args.rows, args.blobsize
    if args.tls:
        TLS = tuple(args.tls)

    seed = connect(target)
    ops = ["ordinals"]
    ops += [{"op": "insert", "table": "ordinals",
             "row": {"number": i, "name": "x" * blob}} for i in range(rows)]
    reply = transact(seed, ops)
    if reply.get("error"):
        sys.exit("ovsdb-stall-client: seed failed: %s" % reply["error"])

    stall = connect(target)
    stall.sendall(json.dumps(
        {"method": "monitor",
         "params": ["ordinals", None,
                    {"ordinals": [{"columns": ["number", "name"]}]}],
         "id": 1}).encode())

    print("READY")
    sys.stdout.flush()
    if args.throttle:
        drain(stall, args.throttle)
    while True:
        time.sleep(60)


if __name__ == '__main__':
    main(sys.argv)
