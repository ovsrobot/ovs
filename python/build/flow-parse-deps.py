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

# Breaks lines read from stdin into groups using blank lines as
# group separators, then sorts lines within the groups for
# reproducibility.


# ovs-test-ofparse is just a wrapper around ovs-ofctl
# that also runs the python flow parsing utility to check that flows are
# parseable

import hashlib
import sys
import os

DEPENDENCIES = ["lib/ofp-actions.c", "lib/odp-util.c"]
DEPENDENCY_FILE = "python/ovs/flows/deps.py"
SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "..")


def usage():
    print(
        """
Usage {cmd} [check | update | list]
Tool to verify flow parsing python code is kept in sync with
flow printing C code.

Commands:
  check:  check the dependencies are met
  update: update the dependencies based on current file content
  list:   list the dependency files
""".format(
            cmd=sys.argv[0]
        )
    )


def digest(filename):
    with open(os.path.join(SRC_DIR, filename), "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def main():
    if len(sys.argv) != 2:
        usage()
        sys.exit(1)

    if sys.argv[1] == "list":
        print(" ".join(DEPENDENCIES))
    elif sys.argv[1] == "update":
        dep_str = list()
        for dep in DEPENDENCIES:
            dep_str.append(
                '    "{dep}": "{digest}"'.format(dep=dep, digest=digest(dep))
            )

        depends = """# File automatically generated. Do not modify manually!
dependencies = {{
{dependencies_dict}
}}""".format(
            dependencies_dict=",\n".join(dep_str)
        )
        with open(os.path.join(SRC_DIR, DEPENDENCY_FILE), "w") as f:
            print(depends, file=f)

    elif sys.argv[1] == "check":
        sys.path.append(os.path.join(SRC_DIR, "python"))
        from ovs.flows.deps import dependencies

        for dep in DEPENDENCIES:
            expected = dependencies.get(dep)
            if not expected or expected != digest(dep):
                print(
                    """
Dependency file {dep} has changed.
Please verify the flow output format has not changed.
If it has changed, modify the python flow parsing code accordingly.

Once you're done, update the dependencies by running '{cmd} update'.
After doing so, check-in the new dependency file.
""".format(
                        dep=dep,
                        cmd=sys.argv[0],
                    )
                )
                return 2
    else:
        usage()
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
