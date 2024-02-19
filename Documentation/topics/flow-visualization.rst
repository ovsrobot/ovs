..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

=====================================================
ovs-flowviz: Datapath and Openflow flow visualization
=====================================================

When troubleshooting networking issues with OVS, we typically end up looking
at OpenFlow or datapath flow dumps. These dumps tend to be quite dense and
difficult to reason about.

``ovs-flowviz`` is a utility script that helps visualizing OpenFlow and
datapath flows to make it easier to understand what is going on.


Installing ovs-flowviz
----------------------

``ovs-flowviz`` is part of the openvswitch python package. To install it, run:
::

    $ pip install openvswitch[flowviz]

Or, if you are working with the OVS tree:
::

    $ cd python && pip install .[flowviz]

Running the tool
----------------
Here is the basic usage of the tool:
::

    $ ovs-flowviz --help
    Usage: ovs-flowviz [OPTIONS] COMMAND [ARGS]...

      OpenvSwitch flow visualization utility.

      It reads openflow and datapath flows (such as the output of ovs-ofctl dump-
      flows or ovs-appctl dpctl/dump-flows) and prints them in different formats.

    Options:
      -c, --config PATH     Use config file  [default: /home/amorenoz/src/ovs/pyth
                            on/venv/lib64/python3.12/site-
                            packages/ovs/flowviz/ovs-flowviz.conf]
      --style TEXT          Select style (defined in config file)
      -i, --input PATH      Read flows from specified filepath. If not provided,
                            flows will be read from stdin. This option can be
                            specified multiple times. Format [alias,]FILENAME.
                            Where alias is a name that shall be used to refer to
                            this FILENAME
      -f, --filter TEXT     Filter flows that match the filter expression.Run
                            'ovs-flowviz filter' for a detailed description of the
                            filtering syntax
      -l, --highlight TEXT  Highlight flows that match the filter expression. Run
                            'ofparse filter' for a detailed description of the
                            filtering syntax
      -h, --help            Show this message and exit.

    Commands:
      datapath  Process Datapath Flows.
      openflow  Process OpenFlow Flows.


Available visualization formats
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``ovs-flowviz`` supports several visualization formats for both OpenFlow and
datapath flows. Here is a summary of the available formats.

.. list-table:: Flow visualization formats
   :widths: 20 20 60
   :header-rows: 1

   * - Flow type
     - Format
     - Description
   * - Openflow
     - console
     - Prints the flows in a configurable, colorful style in the console sorted by table.
   * - Openflow
     - cookie
     - Prints the flows in the console sorted by cookie.
   * - Openflow
     - logic
     - Prints the logical structure of flows in the console.
   * - Openflow
     - html
     - Prints the flows in linked HTML list arranged by tables.
   * - Openflow
     - json
     - Prints the flows in JSON format.
   * - datapath
     - console
     - Prints the flows in a configurable, colorful style in the console.
   * - datapath
     - tree
     - Prints the flows in a tree structure arranged by `recirc_id`.
   * - datapath
     - graph
     - Prints a graphviz graph of the flows arranged by `recirc_id`.
   * - datapath
     - html
     - Prints the flow tree in an collapsable/expandable HTML list.
   * - datapath
     - json
     - Prints the flows in JSON format.


Configuring styles
------------------

A configuration file can provided to the tool in which different styles can be
defined. The tool ships with a default configuration file that includes two
example styles and a description of the configuration syntax (see the source in
``python/ovs/flowviz/ovs-flowviz.conf``). The file can be overriden if the user
creates a personalized file in ``$HOME/.config/ovs/ovs-flowviz```.

Once a style is defined inthe configuration file, it can be used with the
``--style`` option.


Heat Map
~~~~~~~~

Some output commands support heat-map formatting (``--heat-map``) both in
OpenFlow and datapath flow formats.
This option changes the color of the packet and byte counters to reflect their
relative size. The color gradient goes through the following colors:

blue (coldest, lowest), cyan, green, yellow, red (hottest, highest)

Note filtering is typically applied before the range is calculated.


Highlighting and filtering
~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes you want to limit the output or direct your eyes quickly to some
flows. For that purpuse, ``ovs-flowviz`` provides highlighing and filtering,
both using filtering expressions defined as follows.
::

    $ ovs-flowviz filter
    Filter Syntax
      *************

       [! | not ] {key}[[.subkey]...] [OPERATOR] {value})] [LOGICAL OPERATOR] ...

      Comparison operators are:
          =   equality
          <   less than
          >   more than
          ~=  masking (valid for IP and Ethernet fields)

      Logical operators are:
          !{expr}:  NOT
          {expr} && {expr}: AND
          {expr} || {expr}: OR

      Matches and flow metadata:
          To compare against a match or info field, use the field directly, e.g:
              priority=100
              n_bytes>10
          Use simple keywords for flags:
              tcp and ip_src=192.168.1.1

      Actions:
          Actions values might be dictionaries, use subkeys to access individual
          values, e.g:
              output.port=3
          Use simple keywords for flags
              drop

      Examples of valid filters.
          nw_addr~=192.168.1.1 && (tcp_dst=80 || tcp_dst=443)
          arp=true && !arp_tsa=192.168.1.1
          n_bytes>0 && drop=true


Example expressions ::

   n_bytes > 0 and drop
   nw_src~=192.168.1.1 or arp.tsa=192.168.1.1
   ! tcp && output.port=2


Openflow logic format
---------------------

When a controller (such as OVN) writes OpenFlow flows, they typically organize
flows in functional blocks.

For instance, table 1 can implement port security and contain flows that match
on source Ethernet and IP addresses and then ``resubmit`` traffic to the next
table.

Following this example, if there is a large number of ports, we might end up
with a lot of these flows.

Well, the openflow ``logic`` format helps us visualize this as it arranges
flows in *logical blocks* (should not be confused with OVS's logical flows).
A logical block is a set of flows that have:

* Same ``priority``.
* Match on the same fields (regardless of the match value and mask).
* Execute the same actions (regardless of the actions' arguments,
  except for resubmit and output).
* Optinally, the ``cookie`` can be counted as part of the logical flow.


Flows are sorted by table and then by logical flow. Let's see an example.

On a particular (OVN-generated) flow dump we have 26 flows on table 0:
::

   $ grep "table=0" flows.txt | wc -l
   26

However, we can better understand what table 0 does by looking at its
logical representation.
::

   $ ovs-flowviz -i flows.txt -f "table=0" openflow logic
   Ofproto Flows (logical)
   └── ** TABLE 0 **
       ├── priority=180 priority,vlan_tci  --->  conjunction ( x 1 )
       ├── priority=180 priority,conj_id,in_port,vlan_tci  --->  set_field,set_field,set_field,set_field,set_field,set_field resubmit(,8), ( x 1 )
       ├── priority=100 priority,in_port  --->  move,move,move resubmit(,40), ( x 6 )
       ├── priority=100 priority,in_port  --->  set_field,set_field,set_field,set_field,set_field resubmit(,8), ( x 15 )
       ├── priority=100 priority,in_port,vlan_tci  --->  set_field,set_field,set_field,set_field,set_field resubmit(,8), ( x 1 )
       ├── priority=100 priority,in_port,dl_vlan  --->  pop_vlan,set_field,set_field,set_field,set_field,set_field resubmit(,8), ( x 1 )
       └── priority=0 priority  --->   drop, ( x 1 )

In only a few logical blocks, we have a good overview of what this table is
doing. It looks it's adding metadata based on input ports and vlan IDs.

We can also see the flows contained on each logical block with
the ``--show-flows`` option.

ovn-detrace integration
-----------------------

Both **cookie** and **logic** foramts support integration with OVN,
in particula with ovn-detrace utility.

If a recent OVN version is installed, ``ovs-flowviz`` can use the
**ovn-detrace** utility to query OVS's Northbound and Southbound
databases for information on each cookie and print it alongside
the flows.

Datapath flow tree
------------------

Some datapath flow formats deserve some extra explanation.
**html**, **tree** and **graph** datapath formats build a flow tree based
on ``recirc_id``. For example ::

    ── recirc_id(0),in_port(3),eth(...),ipv4(...),tcp(dst=8181), actions:ct(zone=2,nat),recirc(0x19348)
    │   ├── recirc_id(0x19348),in_port(3),ct_state(-new+est-rel-rpl-inv+trk),ct_label(0/0x3),eth(...),eth_type,ipv4(), actions:ct(zone=27,nat),recirc(0x10)
    │   │   ├── recirc_id(0x10),in_port(3),ct_state(-new+est-rel-rpl-inv+trk),eth(...),ipv4(...), actions:9
    │   │   ├── recirc_id(0x10),in_port(3),ct_state(-new+est-rel+rpl-inv+trk),eth(...),ipv4(...), actions:9
    │   │   └── recirc_id(0x10),in_port(3),ct_state(+new-est-rel-rpl-inv+trk),eth(...),ipv4(...), actions:ct(commit,zone=27,label=0/0x1),9
    │   └── recirc_id(0x19348),in_port(3),ct_state(+new-est-rel-rpl-inv+trk),eth(...),ipv4(...),  actions:ct(commit,zone=2,label=0/0x1),ct(zone=27,nat),recirc(0x10)
    │       ├── recirc_id(0x10),in_port(3),ct_state(-new+est-rel-rpl-inv+trk),eth(...),ipv4(...), actions:9
    │       ├── recirc_id(0x10),in_port(3),ct_state(-new+est-rel+rpl-inv+trk),eth(...),ipv4(...), actions:9
    │       └── recirc_id(0x10),in_port(3),ct_state(+new-est-rel-rpl-inv+trk),eth(...),ipv4(...), actions:ct(commit,zone=27,label=0/0x1),9

The above example shows a typical conntrack recirculation flow.
The first flow (with ``recir_id(0)``) sends the packet through conntrack
system and recirculates. Then, based on the ``ct_state`` the packet
processing branches out into two flows. Each flows resends the packet through
conntrack and recirculate the packet one more time. Finally, the packet is
processed by 3 flows on ``recirc_id(10``.

Note that this format can yield longer outputs since some flows (in this
example those with ``recirc_id(10)`` can be repeated. However, the result
is a clear representation of an otherwise difficult to see conntrack
interaction.

This tree can be displayed in the console with the ``tree`` format, in an
interactive HTML table with the ``html`` format on in a directed graph
with the ``graph`` format. The last two formats can be combined together
buy using ``graph --html`` option.


Filtering
~~~~~~~~~

Filtering works in a sligthly different way for datapath flow trees. Unlike
other formats where a filter simply removes non-matching flows, the output
of a filtered datapath flow tree will show full sub-trees that contain at
least one flow that satisfies the filter.

For example, lets take the flows in the above example, and let's imagine we
want to understand what traffic is going out on port ``9``. We could run
the tool as ::

   $ ovs-appctl dpctl/dump-flows | ovs-flowviz -f "output.port=9" datapath tree

The resulting flow tree will contain all of the flows above, even those
with ``recirc_id(0)`` and ``recirc_id(19348)``. Why? because they
are all part of a subtree that contains flows that do output packets on port
9. That way, we see the "full picture" of how traffic on port 9 is being
processed.


JSON representation
-------------------

To print the json representation of a flow run ::

   $ ovs-flowviz {openflow | datapath } json


The output is a json list of json objects each of one representing an
individual flow.
Each flow object contains the following keys.

**orig**
    contains the original flow string
**info**
   contains an object with the flow information
   such as: cookie, duration, table, n_packets, n_bytes, etc
**match**
   contains an object with the flow match.
   For each match, the object contains a key-value where the key is the name
   of the match as defined in ovs-fields and ovs-ofctl and the value
   represents the match value. The way each value is represented depends on its
   type. (See :ref:`value-representation`)
**actions**
   contains a list of action objects.
   Each action is represented by an json object that has one key and one value.
   The key corresponds to the action name. The value represents the arguments
   of such key. See :ref:`action-representation`
   for more details.
**ufid**
   (datpath flows only) contains the ufid


.. _value-representation:

Value representation
~~~~~~~~~~~~~~~~~~~~

Values are represented differently depending on their type:

* Flags: Fields that represent flags (e.g: tcp) are represented by boolean
  "true"
* Decimal / Hexadecimal: They are represented by their integer value.
  If they support masking, they are represented by a dictionary with two keys:
  value contains the field value and mask contains the mask. Both are integers.
* Ethernet: They are represented by a string: {address}[/{mask}]
* IPv4 / IPv6: They are represented by a string {address}[/mask]
* Registers: They are represented by a dictionary with three keys:
  field contains the field value (string), start and end that represent the
  first and last bit of the register. For example, the register ::


   NXM_NX_REG10[0..15]


is represented as ::


   {
       "field": "NXM_NX_REG10",
       "start": 0,
       "end": 15
   },


.. _action-representation:

Action representation
~~~~~~~~~~~~~~~~~~~~~

Actions are generally represented by an object that has a single key and a
value. The key is the action name as defined ovs-actions.

The value of actions that have no arguments (such as ``drop``) is
(boolean) ``true``.

The value of actions that have a list of arguments (e.g:
``resubmit([port],[table],[ct])``) is an object that has the name of the
argument as key. The argument names for each action is defined in
ovs-actions. For example, the action ::

   resubmit(,10)

is represented as ::

   {
       "redirect": {
           "port": "",
           "table": 10
       }
   }

The value of actions that have a key-word list as arguments
(e.g: ``ct([argument])``) is an object whose keys correspond to the keys
defined in ``ovs-actions(7)``. The way values are represented depends
on the type of the argument.
For example, the action ::

   ct(table=14,zone=NXM_NX_REG12[0..15],nat)

is represented as ::

   {
       "ct": {
           "table": 14,
           "zone": {
               "field": "NXM_NX_REG12",
               "start": 0,
               "end": 15
           },
           "nat": true
       }
   }


Examples
--------

Print OpenFlow flows sorted by cookie adding OVN data to each one:
::

    $ ovs-flowviz -i flows.txt openflow cookie --ovn-detrace

Print OpenFlow logical structure, showing the flows and heatmap
::

    $ ovs-flowviz -i flows.txt openflow logic --show-flows --heat-map

Display OpenFlow flows in HTML format with "light" style and highlight drops
::

    $ ovs-flowviz -i flows.txt --style "light" --highlight "n_packets > 0 and drop" openflow html > flows.html

Display the datapath flows in an interactive graphviz + HTML view
::

    $ ovs-flowviz -i flows.txt datapath graph --html > flows.html

Display the datapath flow trees that lead to packets being sent to port 10
::

    $ ovs-flowviz -i flows.txt --filter "output.port=10" datapath tree
