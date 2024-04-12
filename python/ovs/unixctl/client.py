# Copyright (c) 2011, 2012 Nicira, Inc.
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

import os

import ovs.json
import ovs.jsonrpc
import ovs.stream
import ovs.util

vlog = ovs.vlog.Vlog("unixctl_client")


class UnixctlClient(object):
    def __init__(self, conn):
        assert isinstance(conn, ovs.jsonrpc.Connection)
        self._conn = conn

    def transact(self, command, argv, fmt):
        assert isinstance(command, str)
        assert isinstance(argv, list)
        for arg in argv:
            assert isinstance(arg, str)
        assert isinstance(fmt, ovs.util.OutputFormat)

        request = ovs.jsonrpc.Message.create_request(command, argv)
        error, reply = self._conn.transact_block(request)

        if error:
            vlog.warn("error communicating with %s: %s"
                      % (self._conn.name, os.strerror(error)))
            return error, None, None

        def to_string(body):
            if fmt == ovs.util.OutputFormat.TEXT:
                return str(body)
            else:
                return ovs.json.to_string(body)

        if reply.error is not None:
            return 0, to_string(reply.error), None
        else:
            assert reply.result is not None
            return 0, None, to_string(reply.result)

    def close(self):
        self._conn.close()
        self.conn = None

    @staticmethod
    def create(path):
        assert isinstance(path, str)

        unix = "unix:%s" % ovs.util.abs_file_name(ovs.dirs.RUNDIR, path)
        error, stream = ovs.stream.Stream.open_block(
            ovs.stream.Stream.open(unix))

        if error:
            vlog.warn("failed to connect to %s" % path)
            return error, None

        return 0, UnixctlClient(ovs.jsonrpc.Connection(stream))
