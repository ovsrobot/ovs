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

from ovs.flowviz.html_format import HTMLBuffer, HTMLFormatter
from ovs.flowviz.odp.tree import FlowElem, FlowTree
from ovs.flowviz.process import DatapathFactory, FileProcessor


class HTMLTreeProcessor(DatapathFactory, FileProcessor):
    def __init__(self, opts):
        super().__init__(opts)
        self.data = dict()

    def start_file(self, name, filename):
        self.tree = HTMLTree(name, self.opts)

    def process_flow(self, flow, name):
        self.tree.add(flow)

    def process(self):
        super().process(False)

    def stop_file(self, name, filename):
        self.data[name] = self.tree

    def print(self):
        html_obj = ""
        for name, tree in self.data.items():
            html_obj += "<div>"
            html_obj += "<h2>{}</h2>".format(name)
            tree.build()
            if self.opts.get("filter"):
                tree.filter(self.opts.get("filter"))
            html_obj += tree.render()
            html_obj += "</div>"
        print(html_obj)


class HTMLTree(FlowTree):
    """HTMLTree is a Flowtree that prints the tree in html format.

    Args:
        opts(dict): Options dictionary
        flows(dict[int, list[DPFlow]): Optional; initial flows
    """

    html_header = """
    <style>
    .flow{
        background-color:white;
        display: inline-block;
        text-align: left;
        font-family: monospace;
    }
    .active{
        border: 2px solid #0008ff;
    }
    input[type='checkbox'] { display: none; }
    .wrap-collabsible {
        margin: 1.2rem 0;
    }
    .lbl-toggle-main {
        font-weight: bold;
        font-family: monospace;
        font-size: 1.5rem;
        text-transform: uppercase;
        text-align: center;
        padding: 1rem;
        #cursor: pointer;
        border-radius: 7px;
        transition: all 0.25s ease-out;
    }
    .lbl-toggle-flow {
        font-family: monospace;
        font-size: 1.0rem;
        text-transform: uppercase;
        text-align: center;
        padding: 1rem;
        #cursor: pointer;
        border-radius: 7px;
        transition: all 0.25s ease-out;
    }
    .lbl-toggle:hover {
        color: #0008ff;
    }
    .lbl-toggle::before {
        content: ' ';
        display: inline-block;
        border-top: 5px solid transparent;
        border-bottom: 5px solid transparent;
        border-left: 5px solid currentColor;
        vertical-align: middle;
        margin-right: .7rem;
        transform: translateY(-2px);
        transition: transform .2s ease-out;
    }
    .toggle:checked+.lbl-toggle::before {
        transform: rotate(90deg) translateX(-3px);
    }
    .collapsible-content {
        max-height: 0px;
        overflow: hidden;
        transition: max-height .25s ease-in-out;
    }
    .toggle:checked + .lbl-toggle + .collapsible-content {
        max-height: 350px;
    }
    .toggle:checked+.lbl-toggle {
        border-bottom-right-radius: 0;
        border-bottom-left-radius: 0;
    }
    .collapsible-content .content-inner {
        background: rgba(0, 105, 255, .2);
        border-bottom: 1px solid rgba(0, 105, 255, .45);
        border-bottom-left-radius: 7px;
        border-bottom-right-radius: 7px;
        padding: .5rem 1rem;
    }
    .collapsible-content p {
        margin-bottom: 0;
    }
    </style>

    <script>
      function onFlowClick(elem) {
          var flows = document.getElementsByClassName("flow");
          for (i = 0; i < flows.length; i++) {
              flows[i].classList.remove('active')
          }
          elem.classList.add("active");
          var my_toggle = document.getElementsByClassName("flow");
          toggleAll(elem, true);
      }
      function locationHashChanged() {
          var elem = document.getElementById(location.hash.substring(1));
          console.log(elem)
          if (elem) {
            if (elem.classList.contains("flow")) {
                onFlowClick(elem);
            }
          }
      }
      function toggle_checkbox(elem) {
         if (elem.checked == true) {
            toggleAll(elem, true)
         } else {
            toggleAll(elem, false)
         }
      }
      function toggleAll(elem, value) {
          var subs = elem.parentElement.querySelectorAll(".toggle:not([id=" + CSS.escape(elem.id) + "])");
          console.log(subs);
          console.log(value);
          for (i = 0; i < subs.length; ++i) {
              subs[i].checked = value;
          }
      }
      window.onhashchange = locationHashChanged;
    </script>
    """  # noqa: E501

    class HTMLTreeElem(FlowElem):
        """An element within the HTML Tree.

        It is composed of a flow and its subflows that can be added by calling
        append()
        """

        def __init__(self, parent_name, flow=None, opts=None):
            self._parent_name = parent_name
            self._formatter = HTMLFormatter(opts)
            self._opts = opts
            super(HTMLTree.HTMLTreeElem, self).__init__(flow)

        def render(self, item=0):
            """Render the HTML Element.
            Args:
                item (int): the item id

            Returns:
                (html_obj, items) tuple where html_obj is the html string and
                items is the number of subitems rendered in total
            """
            parent_name = self._parent_name.replace(" ", "_")
            html_obj = "<div>"
            if self.flow:
                html_text = """
<input id="collapsible_{name}_{item}" class="toggle" type="checkbox" onclick="toggle_checkbox(this)" checked>
<label for="collapsible_{name}_{item}" class="lbl-toggle lbl-toggle-flow">Flow {id}</label>
            """  # noqa: E501
                html_obj += html_text.format(
                    item=item, id=self.flow.id, name=parent_name
                )

                html_text = '<div class="flow collapsible-content" id="flow_{id}" onfocus="onFlowClick(this)" onclick="onFlowClick(this)" >'  # noqa: E501
                html_obj += html_text.format(id=self.flow.id)
                buf = HTMLBuffer()
                highlighted = None
                if self._opts.get("highlight"):
                    result = self._opts.get("highlight").evaluate(self.flow)
                    if result:
                        highlighted = result.kv
                self._formatter.format_flow(buf, self.flow, highlighted)
                html_obj += buf.text
                html_obj += "</div>"
            if self.children:
                html_obj += "<div>"
                html_obj += "<ul  style='list-style-type:none;'>"
                for sf in self.children:
                    item += 1
                    html_obj += "<li>"
                    (html_elem, items) = sf.render(item)
                    html_obj += html_elem
                    item += items
                    html_obj += "</li>"
                html_obj += "</ul>"
                html_obj += "</div>"
            html_obj += "</div>"
            return html_obj, item

    def __init__(self, name, opts, flows=None):
        self.opts = opts
        self.name = name
        super(HTMLTree, self).__init__(
            flows, self.HTMLTreeElem("", flow=None, opts=self.opts)
        )

    def _new_elem(self, flow, _):
        """Override _new_elem to provide HTMLTreeElems."""
        return self.HTMLTreeElem(self.name, flow, self.opts)

    def render(self):
        """Render the Tree in HTML.

        Returns:
            an html string representing the element
        """
        name = self.name.replace(" ", "_")

        html_text = """<input id="collapsible_main-{name}" class="toggle" type="checkbox" onclick="toggle_checkbox(this)" checked>
<label for="collapsible_main-{name}" class="lbl-toggle lbl-toggle-main">Flow Table</label>"""  # noqa: E501
        html_obj = self.html_header + html_text.format(name=name)

        html_obj += "<div id=flow_list-{name}>".format(name=name)
        (html_elem, _) = self.root.render()
        html_obj += html_elem
        html_obj += "</div>"
        return html_obj
