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

"""ovs-test-dpparse is just a wrapper around ovs-dpctl
that also runs the python flow parsing utility to check that flows are
parseable.
"""
import subprocess
import sys
import re

from ovs.flows.odp import ODPFlow

diff_regexp = re.compile(r"\d{2}: (\d{2}|\(none\)) -> (\d{2}|\(none\))$")


def run(input_data):
    p = subprocess.Popen(
        sys.argv[1:],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = p.communicate(input_data.encode("utf-8"))

    print(out.decode("utf-8"), file=sys.stdout, end="")
    print(err.decode("utf-8"), file=sys.stderr, end="")
    return p.returncode, out, err


def main():
    return_code = 0
    input_data = sys.stdin.read()
    return_code, out, err = run(input_data)

    if return_code == 0:
        flows = list()
        for line in input_data.split("\n"):
            if not (
                "error" in line  # skip errors
                or line.strip() == ""  # skip empty lines
                or line.strip()[0] == "#"  # skip comments
            ):
                flows.append(line)

        for flow in flows:
            if any(
                c in sys.argv
                for c in ["parse-keys", "parse-wc-keys", "parse-filter"]
            ):
                # Add actions=drop so that the flow is properly formatted
                flow += " actions:drop"
            elif "parse-actions" in sys.argv:
                flow = "actions:" + flow
            try:
                result_flow = ODPFlow(flow)
                if flow != str(result_flow):
                    print("in : {}".format(flow))
                    print("out: {}".format(str(result_flow)))
                    raise ValueError("Flow conversion back to string failed!")

            except Exception as e:
                print(e)
                return 1

    return return_code


if __name__ == "__main__":
    sys.exit(main())
