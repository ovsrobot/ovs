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

""" Defines a Datapath Graph using graphviz. """
import colorsys
import graphviz
import random

from ovs.flowviz.odp.html import HTMLTree
from ovs.flowviz.odp.tree import FlowTree
from ovs.flowviz.process import DatapathFactory, FileProcessor


class GraphProcessor(DatapathFactory, FileProcessor):
    def __init__(self, opts):
        super().__init__(opts)

    def start_file(self, name, filename):
        self.tree = FlowTree()

    def process_flow(self, flow, name):
        self.tree.add(flow)

    def process(self):
        super().process(False)

    def print(self, html):
        flows = {}

        # Tree traverse callback
        def add_flow(elem, _):
            if elem.is_root:
                return
            rid = elem.flow.match.get("recirc_id") or 0
            if not flows.get(rid):
                flows[rid] = set()
            flows[rid].add(elem.flow)

        self.tree.build()
        if self.opts.get("filter"):
            self.tree.filter(self.opts.get("filter"))
        self.tree.traverse(add_flow)

        if len(flows) == 0:
            return

        dpg = DatapathGraph(flows)
        if not html:
            print(dpg.source())
            return

        html_obj = ""
        html_obj += "<h1> Flow Graph </h1>"
        html_obj += "<div width=400px height=300px>"
        svg = dpg.pipe(format="svg")
        html_obj += svg.decode("utf-8")
        html_obj += "</div>"
        html_tree = HTMLTree("graph", self.opts, flows)
        html_tree.build()
        html_obj += html_tree.render()

        print(html_obj)


class DatapathGraph:
    """A DatapathGraph is a class that renders a set of datapath flows into
    graphviz graphs.

    Args:
        flows(dict[int, list(Flow)]): Dictionary of lists of flows indexed by
            recirc_id
    """

    ct_styles = {}
    node_styles = {
        "default": {
            "style": {},
            "desc": "Default",
        },
        "action_and_match": {
            "style": {"color": "#ff00ff"},
            "desc": "Flow uses CT as match and action",
        },
        "match": {
            "style": {"color": "#0000ff"},
            "desc": "Flow uses CT only to match",
        },
        "action": {
            "style": {"color": "#ff0000"},
            "desc": "Flow uses CT only as action",
        },
    }

    def __init__(self, flows):
        self._flows = flows

        self._output_nodes = []
        self._graph = graphviz.Digraph(
            "DP flows", node_attr={"shape": "rectangle"}
        )
        self._graph.attr(compound="true")
        self._graph.attr(rankdir="LR")
        self._graph.attr(ranksep="3")

        self._populate_graph()

    def source(self):
        """Return the graphviz source representation of the graph."""
        return self._graph.source

    def pipe(self, *args, **kwargs):
        """Output the graph based on arguments given to graphviz.pipe."""
        return self._graph.pipe(*args, **kwargs)

    @classmethod
    def recirc_cluster_name(cls, recirc_id):
        """Name of the recirculation cluster."""
        return "cluster_recirc_{}".format(hex(recirc_id))

    @classmethod
    def inport_cluster_name(cls, inport):
        """Name of the input port cluster."""
        return "cluster_inport_{}".format(inport)

    @classmethod
    def invis_node_name(cls, cluster_name):
        """Name of the invisible node."""
        return "invis_{}".format(cluster_name)

    @classmethod
    def output_node_name(cls, port):
        """Name of the ouput node."""
        return "output_{}".format(port)

    def _flow_node(self, flow, name):
        """Returns the dictionary of attributes of a graphviz node that
        represents the flow with a given name.
        """
        summary = "Line: {} \n".format(flow.id)
        summary += "\n".join(
            [
                flow.section("info").string,
                ",".join(flow.match.keys()),
                "actions: "
                + ",".join(list(a.keys())[0] for a in flow.actions),
            ]
        )

        has_ct_match = flow.match.get("ct_state", "0/0") != "0/0"
        has_ct_action = bool(
            next(
                filter(lambda x: x.key in ["ct", "ct_clear"], flow.actions_kv),
                None,
            )
        )

        if has_ct_action:
            if has_ct_match:
                style = "action_and_match"
            else:
                style = "action"
        elif has_ct_match:
            style = "match"
        else:
            style = "default"

        style = self.node_styles.get(style, {})

        return {
            "name": name,
            "label": summary,
            "tooltip": flow.orig,
            "_attributes": style.get("style", {}),
            "fontsize": "10",
            "nojustify": "true",
            "URL": "#flow_{}".format(flow.id),
        }

    def _create_recirc_cluster(self, recirc):
        """Process a recirculation id, creating its cluster."""
        cluster_name = self.recirc_cluster_name(recirc)
        label = "recirc x0{:0x}".format(recirc)

        cluster = self._graph.subgraph(name=cluster_name, comment=label)
        with cluster as sg:
            sg.attr(rankdir="TB")
            sg.attr(ranksep="0.02")
            sg.attr(label=label)
            sg.attr(margin="5")
            self._add_flows_to_graph(sg, self._flows[recirc])

        self.processed_recircs.append(recirc)

    def _add_flows_to_graph(self, graph, flows):
        # Create an invisible node and an edge to the first flow so that
        # it ends up at the top of the cluster.
        invis = self.invis_node_name(graph.name)
        graph.node(invis)
        graph.node(
            invis,
            color="white",
            len="0",
            shape="point",
            width="0",
            height="0",
        )
        first = True
        for flow in flows:
            name = "Flow_{}".format(flow.id)
            graph.node(**self._flow_node(flow, name))
            if first:
                with graph.subgraph() as c:
                    c.attr(rank="same")
                    c.edge(name, invis, style="invis")
                first = False
            # determine next hop based on actions
            self._set_next_node_from_actions(name, flow.actions)

    def set_next_node_from_actions(self, name, actions):
        """Determine the next nodes based on action list and add edges to
        them.
        """
        if not self._set_next_node_from_actions(self, name, actions):
            # Add to a generic "End" if no other action was detected
            self._graph.edge(name, "end")

    def _set_next_node_from_actions(self, name, actions):
        created = False
        for action in actions:
            key, value = next(iter(action.items()))
            if key == "check_pkt_len":
                created |= self._set_next_node_from_actions(
                    name, value.get("gt")
                )
                created |= self._set_next_node_from_actions(
                    name, value.get("le")
                )
            elif key == "sample":
                created |= self._set_next_node_from_actions(
                    name, value.get("actions")
                )
            elif key == "clone":
                created |= self._set_next_node_from_actions(
                    name, value.get("actions")
                )
            else:
                created |= self._set_next_node_action(name, key, value)
        return created

    def _set_next_node_action(self, name, action_name, action_obj):
        """Based on the action object, set the next node."""
        if action_name == "recirc":
            # If the targer recirculation cluster has not yet been created,
            # do it now.
            if action_obj not in self.processed_recircs:
                self._create_recirc_cluster(action_obj)

            cname = self.recirc_cluster_name(action_obj)
            self._graph.edge(
                name,
                self.invis_node_name(cname),
                lhead=cname,
                _attributes={"weight": "20"},
            )
            return True
        elif action_name == "output":
            port = action_obj.get("port")
            if port not in self._output_nodes:
                self._output_nodes.append(port)
            self._graph.edge(
                name, self.output_node_name(port), _attributes={"weight": "1"}
            )
            return True
        elif action_name in ["drop", "userspace", "controller"]:
            if action_name not in self._output_nodes:
                self._output_nodes.append(action_name)
            self._graph.edge(name, action_name, _attributes={"weight": "1"})
            return True
        elif action_name == "ct":
            zone = action_obj.get("zone", 0)
            node_name = "CT zone {}".format(action_obj.get("zone", "default"))
            if zone not in self.ct_styles:
                # Pick a random (highly saturated) color.
                (r, g, b) = colorsys.hsv_to_rgb(random.random(), 1, 1)
                color = "#%02x%02x%02x" % (
                    int(r * 255),
                    int(g * 255),
                    int(b * 255),
                )
                self.ct_styles[zone] = color
                self._graph.node(node_name, color=color)

            color = self.ct_styles[zone]
            self._graph.edge(name, node_name, style="dashed", color=color)
            # test
            name = node_name
            return True
        return False

    def _populate_graph(self):
        """Populate the the internal graph."""
        self.processed_recircs = []

        # Create a subcluster for each input port and one for flows that don't
        # have in_port() for which we create a dummy inport.
        flows_per_inport = {}
        free_flows = []

        for flow in self._flows.get(0):
            port = flow.match.get("in_port")
            if port:
                if not flows_per_inport.get(port):
                    flows_per_inport[port] = list()
                flows_per_inport[port].append(flow)
            else:
                free_flows.append(flow)

        # It's rare to find flows without input_port match but let's add them
        # nevertheless.
        if free_flows:
            self._graph.edge(
                "start",
                self.invis_node_name(self.recirc_cluster_name(0)),
                lhead=self.recirc_cluster_name(0),
            )
            self._graph.node("no_port", shape="Mdiamond")

        # Recirc_clusters are created recursively when an edge is found to
        # them.
        # Process recirc(0) which is split by input port.
        for inport, flows in flows_per_inport.items():
            # Build a subgraph per input port
            cluster_name = self.inport_cluster_name(inport)
            label = "recirc 0; input port: {}".format(inport)

            with self._graph.subgraph(
                name=cluster_name, comment=label
            ) as per_port:
                per_port.attr(rankdir="TB")
                per_port.attr(ranksep="0.02")
                per_port.attr(margin="5")
                per_port.attr(label=label)
                self._add_flows_to_graph(per_port, flows_per_inport[inport])

        # Create an input node that points to each input subgraph
        # They are all inside an anonymous subgraph so that they can be
        # alligned.
        with self._graph.subgraph() as s:
            s.attr(rank="same")
            for inport in flows_per_inport:
                # Make an Input node point to each subgraph
                node_name = "input_{}".format(inport)
                cluster_name = self.inport_cluster_name(inport)
                s.node(
                    node_name,
                    shape="Mdiamond",
                    label="input port {}".format(inport),
                )
                self._graph.edge(
                    node_name,
                    self.invis_node_name(cluster_name),
                    lhead=cluster_name,
                    _attributes={"weight": "20"},
                )

        # Create the output nodes in a subgraph so that they are alligned
        with self._graph.subgraph() as s:
            for port in self._output_nodes:
                s.attr(rank="same")
                if port == "drop":
                    s.node(
                        "drop",
                        shape="Msquare",
                        color="red",
                        label="DROP",
                        rank="sink",
                    )
                elif port == "controller":
                    s.node(
                        "controller",
                        shape="Msquare",
                        color="blue",
                        label="CONTROLLER",
                        rank="sink",
                    )
                elif port == "userspace":
                    s.node(
                        "userspace",
                        shape="Msquare",
                        color="blue",
                        label="CONTROLLER",
                        rank="sink",
                    )
                else:
                    s.node(
                        self.output_node_name(port),
                        shape="Msquare",
                        color="green",
                        label="Port {}".format(port),
                        rank="sink",
                    )

        # Print style legend
        with self._graph.subgraph(name="cluster_legend") as s:
            s.attr(label="Legend")
            for style in self.node_styles.values():
                s.node(name=style.get("desc"), _attributes=style.get("style"))
