#!/usr/bin/env python3
# Copyright (c) 2021 Red Hat, Inc.
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

"""ovs-test-ofparse is just a wrapper around ovs-ofctl
that also runs the python flow parsing utility to check that flows are
parseable.
"""

import subprocess
import sys
import re

from ovs.flows.ofp import OFPFlow

diff_regexp = re.compile(r"\d{2}: (\d{2}|\(none\)) -> (\d{2}|\(none\))$")


def run_ofctl(with_stdin):
    cmd = sys.argv
    cmd[0] = "ovs-ofctl"
    if with_stdin:
        p = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        input_data = sys.stdin.read()
        out, err = p.communicate(input_data.encode("utf-8"))

        print(out.decode("utf-8"), file=sys.stdout, end="")
        print(err.decode("utf-8"), file=sys.stderr, end="")
        return p.returncode, out, err
    else:
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = p.communicate()

        print(out.decode("utf-8"), file=sys.stdout, end="")
        print(err.decode("utf-8"), file=sys.stderr, end="")
        return p.returncode, out, err


def main():
    flows = list()
    return_code = 0

    if "parse-actions" in sys.argv:
        return_code, out, err = run_ofctl(True)

        out_lines = out.decode("utf-8").split("\n")
        for line in out_lines:
            if not (
                "bad" in line  # skip "bad action at..."
                or line.strip() == ""  # skip empty lines
                or diff_regexp.match(line)  # skip differences
            ):
                flows.append(line)

    elif "add-flow" in sys.argv:
        return_code, out, err = run_ofctl(False)
        flows.append(sys.argv[-1])

    elif "dump-flows" in sys.argv:
        return_code, out, err = run_ofctl(False)
        out_lines = out.decode("utf-8").split("\n")

        for line in out_lines:
            if not (
                "reply" in line  # skip NXST_FLOW reply:
                or line.strip() == ""  # skip empty lines
            ):
                flows.append(line)
    else:
        print("Unsupported command: {}".format(sys.argv))
        sys.exit(1)

    if return_code == 0:
        for flow in flows:
            try:
                result_flow = OFPFlow(flow)
                if flow != str(result_flow):
                    print("in: {}".format(flow))
                    print("out: {}".format(str(result_flow)))
                    raise ValueError("Flow conversion back to string failed")
            except Exception as e:
                print(e)
                return 1

    return return_code


if __name__ == "__main__":
    sys.exit(main())
