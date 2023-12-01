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

from rich.style import Style
from rich.text import Text
from rich.tree import Tree

from ovs.flowviz.console import (
    ConsoleFormatter,
    ConsoleBuffer,
    hash_pallete,
    heat_pallete,
    file_header,
)
from ovs.flowviz.process import (
    DatapathFactory,
    FileProcessor,
)


class TreeElem:
    """Element in the tree.
    Args:
        children (list[TreeElem]): Optional, list of children
        is_root (bool): Optional; whether this is the root elemen
    """

    def __init__(self, children=None, is_root=False):
        self.children = children or list()
        self.is_root = is_root

    def append(self, child):
        self.children.append(child)


class FlowElem(TreeElem):
    """An element that contains a flow.
    Args:
        flow (Flow): The flow that this element contains
        children (list[TreeElem]): Optional, list of children
        is_root (bool): Optional; whether this is the root elemen
    """

    def __init__(self, flow, children=None, is_root=False):
        self.flow = flow
        super(FlowElem, self).__init__(children, is_root)

    def evaluate_any(self, filter):
        """Evaluate the filter on the element and all its children.
        Args:
            filter(OFFilter): the filter to evaluate

        Returns:
            True if ANY of the flows (including self and children) evaluates
            true
        """
        if filter.evaluate(self.flow):
            return True

        return any([child.evaluate_any(filter) for child in self.children])


class FlowTree:
    """A Flow tree is a a class that processes datapath flows into a tree based
    on recirculation ids.

    Args:
        flows (list[ODPFlow]): Optional, initial list of flows or dictionary of
        flows indexed by recirc_id
        root (TreeElem): Optional, root of the tree.
    """

    def __init__(self, flows=None, root=TreeElem(is_root=True)):
        self._flows = {}
        self.root = root
        if flows:
            if isinstance(flows, dict):
                self._flows = flows
            elif isinstance(flows, list):
                for flow in flows:
                    self.add(flow)
            else:
                raise Exception(
                    "flows in wrong format: {}".format(type(flows))
                )

    def add(self, flow):
        """Add a flow"""
        rid = flow.match.get("recirc_id") or 0
        if not self._flows.get(rid):
            self._flows[rid] = list()
        self._flows[rid].append(flow)

    def build(self):
        """Build the flow tree."""
        self._build(self.root, 0)

    def traverse(self, callback):
        """Traverses the tree calling callback on each element.

        callback: callable that accepts two TreeElem, the current one being
            traversed and its parent
            func callback(elem, parent):
                ...
            Note that "parent" can be None if it's the first element.
        """
        self._traverse(self.root, None, callback)

    def _traverse(self, elem, parent, callback):
        callback(elem, parent)

        for child in elem.children:
            self._traverse(child, elem, callback)

    def _build(self, parent, recirc):
        """Build the subtree starting at a specific recirc_id. Recursive function.

        Args:
            parent (TreeElem): parent of the (sub)tree
            recirc(int): the recirc_id subtree to build
        """
        flows = self._flows.get(recirc)
        if not flows:
            return
        for flow in sorted(
            flows, key=lambda x: x.info.get("packets") or 0, reverse=True
        ):
            next_recircs = self._get_next_recirc(flow)

            elem = self._new_elem(flow, parent)
            parent.append(elem)

            for next_recirc in next_recircs:
                self._build(elem, next_recirc)

    def _get_next_recirc(self, flow):
        """Get the next recirc_ids from a Flow.

        The recirc_id is obtained from actions such as recirc, but also
        complex actions such as check_pkt_len and sample
        Args:
            flow (ODPFlow): flow to get the recirc_id from.
        Returns:
            set of next recirculation ids.
        """

        # Helper function to find a recirc in a dictionary of actions.
        def find_in_list(actions_list):
            recircs = []
            for item in actions_list:
                (action, value) = next(iter(item.items()))
                if action == "recirc":
                    recircs.append(value)
                elif action == "check_pkt_len":
                    recircs.extend(find_in_list(value.get("gt")))
                    recircs.extend(find_in_list(value.get("le")))
                elif action == "clone":
                    recircs.extend(find_in_list(value))
                elif action == "sample":
                    recircs.extend(find_in_list(value.get("actions")))
            return recircs

        recircs = []
        recircs.extend(find_in_list(flow.actions))

        return set(recircs)

    def _new_elem(self, flow, _):
        """Creates a new TreeElem.

        Default implementation is to create a FlowElem. Derived classes can
        override this method to return any derived TreeElem
        """
        return FlowElem(flow)

    def filter(self, filter):
        """Removes the first level subtrees if none of its sub-elements match
        the filter.

        Args:
            filter(OFFilter): filter to apply
        """
        to_remove = list()
        for l0 in self.root.children:
            passes = l0.evaluate_any(filter)
            if not passes:
                to_remove.append(l0)
        for elem in to_remove:
            self.root.children.remove(elem)

    def all(self):
        """Return all the flows in a dictionary by recirc_id."""
        return self._flows


class ConsoleTreeProcessor(DatapathFactory, FileProcessor):
    def __init__(self, opts):
        super().__init__(opts)
        self.data = dict()
        self.ofconsole = ConsoleFormatter(self.opts)

        # Generate a color pallete for cookies
        recirc_style_gen = hash_pallete(
            hue=[x / 50 for x in range(0, 50)], saturation=[0.7], value=[0.8]
        )

        style = self.ofconsole.style
        style.set_default_value_style(Style(color="grey66"))
        style.set_key_style("output", Style(color="green"))
        style.set_value_style("output", Style(color="green"))
        style.set_value_style("recirc", recirc_style_gen)
        style.set_value_style("recirc_id", recirc_style_gen)

    def start_file(self, name, filename):
        self.tree = ConsoleTree(self.ofconsole, self.opts)

    def process_flow(self, flow, name):
        self.tree.add(flow)

    def process(self):
        super().process(False)

    def stop_file(self, name, filename):
        self.data[name] = self.tree

    def print(self, heat_map):
        for name, tree in self.data.items():
            self.ofconsole.console.print("\n")
            self.ofconsole.console.print(file_header(name))
            tree.build()
            if self.opts.get("filter"):
                tree.filter(self.opts.get("filter"))
            tree.print(heat_map)


class ConsoleTree(FlowTree):
    """ConsoleTree is a FlowTree that prints the tree in the console.

    Args:
        console (ConsoleFormatter): console to use for printing
        opts (dict): Options dictionary
    """

    class ConsoleElem(FlowElem):
        def __init__(self, flow=None, is_root=False):
            self.tree = None
            super(ConsoleTree.ConsoleElem, self).__init__(
                flow, is_root=is_root
            )

    def __init__(self, console, opts):
        self.console = console
        self.opts = opts
        super(ConsoleTree, self).__init__(root=self.ConsoleElem(is_root=True))

    def _new_elem(self, flow, _):
        """Override _new_elem to provide ConsoleElems"""
        return self.ConsoleElem(flow)

    def _append_to_tree(self, elem, parent):
        """Callback to be used for FlowTree._build
        Appends the flow to the rich.Tree
        """
        if elem.is_root:
            elem.tree = Tree("Datapath Flows (logical)")
            return

        buf = ConsoleBuffer(Text())
        highlighted = None
        if self.opts.get("highlight"):
            result = self.opts.get("highlight").evaluate(elem.flow)
            if result:
                highlighted = result.kv
        self.console.format_flow(buf, elem.flow, highlighted)
        elem.tree = parent.tree.add(buf.text)

    def print(self, heat=False):
        """Print the Flow Tree.
        Args:
            heat (bool): Optional; whether heat-map style shall be applied
        """
        if heat:
            for field in ["packets", "bytes"]:
                values = []
                for flow_list in self._flows.values():
                    values.extend([f.info.get(field) or 0 for f in flow_list])
                self.console.style.set_value_style(
                    field, heat_pallete(min(values), max(values))
                )
        self.traverse(self._append_to_tree)
        self.console.console.print(self.root.tree)
