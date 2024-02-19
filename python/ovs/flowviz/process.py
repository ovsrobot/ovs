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

import sys
import json
import click

from ovs.flow.decoders import FlowEncoder
from ovs.flow.odp import ODPFlow
from ovs.flow.ofp import OFPFlow


class FileProcessor(object):
    """Base class for file-based Flow processing. It is able to create flows
    from strings found in a file (or stdin).

    The process of parsing the flows is extendable in many ways by deriving
    this class.

    When process() is called, the base class will:
        - call self.start_file() for each new file that get's processed
        - call self.create_flow() for each flow line
        - apply the filter defined in opts if provided (can be optionally
            disabled)
        - call self.process_flow() for after the flow has been filtered
        - call self.stop_file() after the file has been processed entirely

    In the case of stdin, the filename and file alias is 'stdin'.

    Child classes must at least implement create_flow() and process_flow()
    functions.

    Args:
        opts (dict): Options dictionary
    """

    def __init__(self, opts):
        self.opts = opts

    # Methods that must be implemented by derived classes.
    def init(self):
        """Called before the flow processing begins."""
        pass

    def start_file(self, alias, filename):
        """Called before the processing of a file begins.
        Args:
            alias(str): The alias name of the filename
            filename(str): The filename string
        """
        pass

    def create_flow(self, line, idx):
        """Called for each line in the file.
        Args:
            line(str): The flow line
            idx(int): The line index

        Returns a Flow.
        Must be implemented by child classes.
        """
        raise NotImplementedError

    def process_flow(self, flow, name):
        """Called for built flow (after filtering).
        Args:
            flow(Flow): The flow created by create_flow
            name(str): The name of the file from which the flow comes
        """
        raise NotImplementedError

    def stop_file(self, alias, filename):
        """Called after the processing of a file ends.
        Args:
            alias(str): The alias name of the filename
            filename(str): The filename string
        """
        pass

    def end(self):
        """Called after the processing ends."""
        pass

    def process(self, do_filter=True):
        idx = 0
        filenames = self.opts.get("filename")
        filt = self.opts.get("filter") if do_filter else None
        self.init()
        if filenames:
            for alias, filename in filenames:
                try:
                    with open(filename) as f:
                        self.start_file(alias, filename)
                        for line in f:
                            flow = self.create_flow(line, idx)
                            idx += 1
                            if not flow or (filt and not filt.evaluate(flow)):
                                continue
                            self.process_flow(flow, alias)
                        self.stop_file(alias, filename)
                except IOError as e:
                    raise click.BadParameter(
                        "Failed to read from file {} ({}): {}".format(
                            filename, e.errno, e.strerror
                        )
                    )
        else:
            data = sys.stdin.read()
            self.start_file("stdin", "stdin")
            for line in data.split("\n"):
                line = line.strip()
                if line:
                    flow = self.create_flow(line, idx)
                    idx += 1
                    if (
                        not flow
                        or not getattr(flow, "_sections", None)
                        or (filt and not filt.evaluate(flow))
                    ):
                        continue
                    self.process_flow(flow, "stdin")
            self.stop_file("stdin", "stdin")
        self.end()


class DatapathFactory():
    """A mixin class that creates Datapath flows."""

    def create_flow(self, line, idx):
        # Skip strings commonly found in Datapath flow dumps.
        if any(s in line for s in [
            "flow-dump from the main thread",
            "flow-dump from pmd on core",
        ]):
            return None

        return ODPFlow(line, idx)


class OpenFlowFactory():
    """A mixin class that creates OpenFlow flows."""

    def create_flow(self, line, idx):
        # Skip strings commonly found in OpenFlow flow dumps.
        if " reply " in line:
            return None

        return OFPFlow(line, idx)


class JSONProcessor(FileProcessor):
    """A FileProcessor that prints flows in JSON format."""

    def __init__(self, opts):
        super().__init__(opts)
        self.flows = dict()

    def start_file(self, name, filename):
        self.flows_list = list()

    def stop_file(self, name, filename):
        self.flows[name] = self.flows_list

    def process_flow(self, flow, name):
        self.flows_list.append(flow)

    def json_string(self):
        if len(self.flows.keys()) > 1:
            return json.dumps(
                [
                    {"name": name, "flows": [flow.dict() for flow in flows]}
                    for name, flows in self.flows.items()
                ],
                indent=4,
                cls=FlowEncoder,
            )
        return json.dumps(
            [flow.dict() for flow in self.flows_list],
            indent=4,
            cls=FlowEncoder,
        )
