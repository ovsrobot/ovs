# Copyright (c) 2023 Red Hat, Inc.
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

import click

from ovs.flowviz.main import maincli
from ovs.flowviz.process import (
    ConsoleProcessor,
    OpenFlowFactory,
    JSONProcessor,
)


@maincli.group(subcommand_metavar="FORMAT")
@click.pass_obj
def openflow(opts):
    """Process OpenFlow Flows."""
    pass


class JSONPrint(OpenFlowFactory, JSONProcessor):
    def __init__(self, opts):
        super().__init__(opts)


@openflow.command()
@click.pass_obj
def json(opts):
    """Print the flows in JSON format."""
    proc = JSONPrint(opts)
    proc.process()
    print(proc.json_string())


class OFConsoleProcessor(OpenFlowFactory, ConsoleProcessor):
    def __init__(self, opts, heat_map):
        super().__init__(opts, heat_map)


@openflow.command()
@click.option(
    "-h",
    "--heat-map",
    is_flag=True,
    default=False,
    show_default=True,
    help="Create heat-map with packet and byte counters",
)
@click.pass_obj
def console(opts, heat_map):
    """Print the flows in the console with some style."""
    proc = OFConsoleProcessor(
        opts,
        heat_map=["n_packets", "n_bytes"] if heat_map else [],
    )
    proc.process()
    proc.print()
