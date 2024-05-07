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

from ovs.flowviz.html_format import HTMLBuffer, HTMLFormatter, HTMLStyle
from ovs.flowviz.process import (
    OpenFlowFactory,
    FileProcessor,
)


class HTMLProcessor(OpenFlowFactory, FileProcessor):
    """File processor that prints Openflow tables in HTML."""

    def __init__(self, opts):
        super().__init__(opts)
        self.data = dict()

    def start_file(self, name, filename):
        self.tables = dict()

    def stop_file(self, name, filename):
        self.data[name] = self.tables

    def process_flow(self, flow, name):
        table = flow.info.get("table") or 0
        if not self.tables.get(table):
            self.tables[table] = list()
        self.tables[table].append(flow)

    def html(self):
        html_obj = ""
        for name, tables in self.data.items():
            name = name.replace(" ", "_")
            html_obj += "<h1>{}</h1>".format(name)
            html_obj += "<div id=flow_list>"
            for table, flows in tables.items():
                formatter = HTMLFormatter(self.opts)

                def anchor(x):
                    return "#table_%s_%s" % (name, x.value["table"])

                formatter.style.set_value_style(
                    "resubmit",
                    HTMLStyle(
                        formatter.style.get("value.resubmit"),
                        anchor_gen=anchor,
                    ),
                )
                html_obj += (
                    "<h2 id=table_{name}_{table}> Table {table}</h2>".format(
                        name=name, table=table
                    )
                )
                html_obj += "<ul id=table_{}_flow_list>".format(table)
                for flow in flows:
                    html_obj += "<li id=flow_{}>".format(flow.id)
                    highlighted = None
                    if self.opts.get("highlight"):
                        result = self.opts.get("highlight").evaluate(flow)
                        if result:
                            highlighted = result.kv
                    buf = HTMLBuffer()
                    formatter.format_flow(buf, flow, highlighted)
                    html_obj += buf.text
                    html_obj += "</li>"
                html_obj += "</ul>"
            html_obj += "</div>"

        return html_obj
