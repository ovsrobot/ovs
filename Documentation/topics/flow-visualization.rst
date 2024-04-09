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

==================================
Visualizing flows with ovs-flowviz
==================================

When troubleshooting networking issues with OVS, we typically end up looking
at OpenFlow or datapath flow dumps. These dumps tend to be quite dense and
difficult to reason about.

``ovs-flowviz`` is a utility script that helps visualizing OpenFlow and
datapath flows to make it easier to understand what is going on.

The `ovs-flowviz(8)`_ manpage describes its basic usage. In this document a few
of its advanced visualization formats will be expanded.


Installing ovs-flowviz
----------------------

``ovs-flowviz`` is part of the openvswitch python package but its
extra dependencies have to be installed explicitly by running:
::

    $ pip install openvswitch[flowviz]

Or, if you are working with the OVS tree:
::

    $ cd python && pip install .[flowviz]

Visualizing OpenFlow logical block
----------------------------------

When controllers such as OVN write OpenFlow flows, they typically organize
flows in functional blocks. These blocks can expand to multiple flows that
"look similar", in the sense that they match on the same fields and have
similar actions.

However, when we look at a flow dump the number of flows can make it difficult
to perceive this logical functionality that the controller is trying to
implement using OpenFlow.

In this example, we are going to use ``ovs-flowviz openflow logic``
visualization to understand an OVN flow dump a bit better.

On a particular flow dump we have 23 flows in table 0:
::

   $ grep -c "table=0" flows.txt
   23

If we look at the first few lines, the amount of information can be
overwhelming and difficult our analysis:

::

    $ head flows.txt
      cookie=0xf76b4b20, duration=765.107s, table=0, n_packets=0, n_bytes=0, priority=180,vlan_tci=0x0000/0x1000 actions=conjunction(100,2/2)
      cookie=0xf76b4b20, duration=765.107s, table=0, n_packets=0, n_bytes=0, priority=180,conj_id=100,in_port="patch-br-int-to",vlan_tci=0x0000/0x1000 actions=load:0xa->NXM_NX_REG13[],load:0xc->NXM_NX_REG11[],load:0xb->NXM_NX_REG12[],load:0xb->OXM_OF_METADATA[],load:0x1->NXM_NX_REG14[],mod_dl_src:02:42:ac:12:00:03,resubmit(,8)
      cookie=0x0, duration=765.388s, table=0, n_packets=0, n_bytes=0, priority=100,in_port="ovn-6bb3b3-0" actions=move:NXM_NX_TUN_ID[0..23]->OXM_OF_METADATA[0..23],move:NXM_NX_TUN_METADATA0[16..30]->NXM_NX_REG14[0..14],move:NXM_NX_TUN_METADATA0[0..15]->NXM_NX_REG15[0..15],resubmit(,40)
      cookie=0x0, duration=765.388s, table=0, n_packets=0, n_bytes=0, priority=100,in_port="ovn-a6ff98-0" actions=move:NXM_NX_TUN_ID[0..23]->OXM_OF_METADATA[0..23],move:NXM_NX_TUN_METADATA0[16..30]->NXM_NX_REG14[0..14],move:NXM_NX_TUN_METADATA0[0..15]->NXM_NX_REG15[0..15],resubmit(,40)
      cookie=0xf2ca6195, duration=765.107s, table=0, n_packets=6, n_bytes=636, priority=100,in_port="ovn-k8s-mp0" actions=load:0x1->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x2->NXM_NX_REG14[],resubmit(,8)
      cookie=0x236e941d, duration=408.874s, table=0, n_packets=11, n_bytes=846, priority=100,in_port=aceac9829941d11 actions=load:0x11->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x3->NXM_NX_REG14[],resubmit(,8)
      cookie=0x3facf689, duration=405.581s, table=0, n_packets=11, n_bytes=846, priority=100,in_port="363ba22029cd92b" actions=load:0x12->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x4->NXM_NX_REG14[],resubmit(,8)
      cookie=0xe7c8c4bb, duration=405.570s, table=0, n_packets=11, n_bytes=846, priority=100,in_port="6a62cde0d50ef44" actions=load:0x13->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x5->NXM_NX_REG14[],resubmit(,8)
      cookie=0x99a0ffc1, duration=59.391s, table=0, n_packets=8, n_bytes=636, priority=100,in_port="5ff3bfaaa4eb622" actions=load:0x14->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x6->NXM_NX_REG14[],resubmit(,8)
      cookie=0xe1b5c263, duration=59.365s, table=0, n_packets=8, n_bytes=636, priority=100,in_port="8d9e0bc76347e59" actions=load:0x15->NXM_NX_REG13[],load:0x2->NXM_NX_REG11[],load:0x7->NXM_NX_REG12[],load:0x4->OXM_OF_METADATA[],load:0x7->NXM_NX_REG14[],resubmit(,8)


However, we can better understand what table 0 does by looking at its
logical representation.
::

   $ ovs-flowviz -i flows.txt -f "table=0" openflow logic
    Ofproto Flows (logical)
    └── ** TABLE 0 **
        ├── priority=180 priority,vlan_tci  --->  conjunction ( x 1 )
        ├── priority=180 priority,conj_id,in_port,vlan_tci  --->  load,load,load,load,load,mod_dl_src resubmit(,8), ( x 1 )
        ├── priority=100 priority,in_port  --->  move,move,move resubmit(,40), ( x 2 )
        ├── priority=100 priority,in_port  --->  load,load,load,load,load resubmit(,8), ( x 16 )
        ├── priority=100 priority,in_port,vlan_tci  --->  load,load,load,load,load resubmit(,8), ( x 1 )
        ├── priority=100 priority,in_port,dl_vlan  --->  strip_vlan,load,load,load,load,load resubmit(,8), ( x 1 )
        └── priority=0 priority  --->   drop, ( x 1 )


In only a few logical blocks, we have a good overview of what this table is
doing. It looks like it's adding metadata based on input ports and vlan
IDs and mainly sending traffic to table 8.

Let's look at table 8, an in this case, let's filter out the flows that have
not been hit by actual traffic. This is quite easy to do with the arithmetic
filtering expressions:
::

   $ ovs-flowviz -i flows.txt -f "table=8 and n_packets>0" openflow logic

    Ofproto Flows (logical)
    └── ** TABLE 8 **
        ├── priority=50 priority,reg14,metadata,dl_dst  --->  load resubmit(,9), ( x 3 )
        └── priority=50 priority,metadata  --->  load,move resubmit(,73),resubmit(,9), ( x 2 )

At this point, we might find ourselves a bit lost since we may not remember
what metadata OVN stored in the previous table. Here is where
``ovs-flowviz``'s OVN integration could come useful. Let's connect to the
running OVN instance and ask it about the flows we're looking at.

::

    $ export OVN_NB_DB=tcp:172.18.0.4:6641
    $ export OVN_SB_DB=tcp:172.18.0.4:6642
    $ ovs-flowviz -i flows.txt -f "table=8 and n_packets>0" openflow logic --ovn-detrace
    Ofproto Flows (logical)
    └── ** TABLE 8 **
        ├── cookie=0xe10c34ee priority=50 priority,reg14,metadata,dl_dst  --->  load resubmit(,9), ( x 1 )
        │   └── OVN Info
        │       ├── *  Logical datapaths:
        │       ├── *      "ovn_cluster_router" (366e1c41-0f3d-4420-b796-10692b64e3e4)
        │       ├── *  Logical flow: table=0 (lr_in_admission), priority=50, match=(eth.mcast && inport == "rtos-ovn-worker2), actions=(xreg0[0..47] = 0a:58:0a:f4:01:01; next;)
        │       └── *  Logical Router Port: rtos-ovn-worker2 mac 0a:58:0a:f4:01:01 networks ['10.244.1.1/24'] ipv6_ra_configs {}
        ├── cookie=0x11e1adbc priority=50 priority,reg14,metadata,dl_dst  --->  load resubmit(,9), ( x 1 )
        │   └── OVN Info
        │       ├── *  Logical datapaths:
        │       ├── *      "GR_ovn-worker2" (c07f8387-6479-4e81-9304-9f8e54f81c56)
        │       ├── *  Logical flow: table=0 (lr_in_admission), priority=50, match=(eth.mcast && inport == "rtoe-GR_ovn-worker2), actions=(xreg0[0..47] = 02:42:ac:12:00:03; next;)
        │       └── *  Logical Router Port: rtoe-GR_ovn-worker2 mac 02:42:ac:12:00:03 networks ['172.18.0.3/16'] ipv6_ra_configs {}
        ├── cookie=0xf42133f  priority=50 priority,reg14,metadata,dl_dst  --->  load resubmit(,9), ( x 1 )
        │   └── OVN Info
        │       ├── *  Logical datapaths:
        │       ├── *      "GR_ovn-worker2" (c07f8387-6479-4e81-9304-9f8e54f81c56)
        │       ├── *  Logical flow: table=0 (lr_in_admission), priority=50, match=(eth.dst == 02:42:ac:12:00:03 && inport == "rtoe-GR_ovn-worker2), actions=(xreg0[0..47] = 02:42:ac:12:00:03; next;)
        │       └── *  Logical Router Port: rtoe-GR_ovn-worker2 mac 02:42:ac:12:00:03 networks ['172.18.0.3/16'] ipv6_ra_configs {}
        └── cookie=0x43a0327  priority=50 priority,metadata  --->  load,move resubmit(,73),resubmit(,9), ( x 2 )
            └── OVN Info
                ├── *  Logical datapaths:
                ├── *      "ovn-worker" (24280d0b-fee0-4f8e-ba4f-036a9b9af921)
                ├── *      "ovn-control-plane" (3262a782-8961-416b-805e-08233e8fda72)
                ├── *      "ext_ovn-worker2" (3f88dcd2-c56d-478f-a3b1-c7aee2efe967)
                ├── *      "ext_ovn-worker" (5facbaf0-485d-4cf5-8940-eff9678ef7bb)
                ├── *      "ext_ovn-control-plane" (8b0aecb6-b05a-48a7-ad09-72524bb91d40)
                ├── *      "join" (e2dc230e-2f2a-4b93-93fa-0fe495163514)
                ├── *      "ovn-worker2" (f7709fbf-d728-4cff-9b9b-150461cc75d2)
                └── *  Logical flow: table=0 (ls_in_check_port_sec), priority=50, match=(1), actions=(reg0[15] = check_in_port_sec(); next;)

That's way better. ``ovs-flowviz`` has automatically added the `cookie` to the
logical block key so have more blocks but in exchange, it has looked up each
cookie on the running OVN databases and inserted the known information on each
block. So now we see what OVN is trying to do, the logical flow that generated
each OpenFlow flow and the logical datapath each flow belongs to.

Visualizing datapath flow trees
-------------------------------

Now, let's see another typical usecase that can lead to eyestrain:
understanding datapath conntrack recirculations.

OVS makes heavy use of connection tracking and the ``recirc()`` action
to build complex datapaths. Typically, OVS will insert a flow that,
when matched, will send the packet through conntrack (using the ``ct`` action)
and recirculate it with a particular recirculation id (``recirc_id``). Then, a
flow matching on that ``recirc_id`` will be matched and further process the
packet. This can happen more than once for a given packet.

This sequential set of events is, however, difficult to visualize when you
look at a datapath flow dump. Flows are unordered recirculations that need to
be followed manually (typically, with heavy use of "grep").

For this use-case, ``ovs-flowviz datapath tree`` format can be extremely
useful. It builds a hierarchical tree based on the ``recirc_id`` matches and
``recirc()`` actions and indents flows based on it.

Here is an example.
::

    ── recirc_id(0),in_port(3),eth(...),ipv4(...),tcp(dst=8181), actions:ct(zone=2,nat),recirc(0x19348)
    │   ├── recirc_id(0x19348),in_port(3),ct_state(-new+est-rel-rpl-inv+trk),ct_label(0/0x3),eth(...),eth_type,ipv4(), actions:ct(zone=27,nat),recirc(0x10)
    │   │   ├── recirc_id(0x10),in_port(3),ct_state(-new+est-rel-rpl-inv+trk),eth(...),ipv4(...), actions:9
    │   │   ├── recirc_id(0x10),in_port(3),ct_state(-new+est-rel+rpl-inv+trk),eth(...),ipv4(...), actions:9
    │   │   └── recirc_id(0x10),in_port(3),ct_state(+new-est-rel-rpl-inv+trk),eth(...),ipv4(...), actions:ct(commit,zone=27,label=0/0x1),9
    │   └── recirc_id(0x19348),in_port(3),ct_state(+new-est-rel-rpl-inv+trk),eth(...),ipv4(...),  actions:ct(commit,zone=2,label=0/0x1),ct(zone=27,nat),recirc(0x10)
    │       ├── recirc_id(0x10),in_port(3),ct_state(-new+est-rel-rpl-inv+trk),eth(...),ipv4(...), actions:9
    │       ├── recirc_id(0x10),in_port(3),ct_state(-new+est-rel+rpl-inv+trk),eth(...),ipv4(...), actions:9
    │       └── recirc_id(0x10),in_port(3),ct_state(+new-est-rel-rpl-inv+trk),eth(...),ipv4(...), actions:ct(commit,zone=27,label=0/0x1),9

The above shows a typical conntrack recirculation flow.
The first flow (with ``recir_id(0)``) sends the packet through conntrack
system and recirculates with ``recirc_id(0x19348)``.
Then, based on the ``ct_state`` the packet processing branches out into two
flows. Each flow resends the packet through conntrack and recirculates the
packet one more time. Finally, the packet is processed by 3 flows
on ``recirc_id(10)``.

This 3-stage processing is now very clear.

Note that this format can yield longer outputs since some flows (in this
example those with ``recirc_id(10)`` can be repeated. However, the result
is a clear representation of an otherwise difficult to see conntrack
interaction.

This example shows only a single "subtree". If we use this command to display
a big flow dump, the output can be lengthy. Here are two (combinable) ways to
help out.

Plotting datapath trees
~~~~~~~~~~~~~~~~~~~~~~~

By using the ``ovs-flowviz datapath html`` format, long datapath trees can
be displayed in an interactive HTML table. The resulting web allows you to
collapse and expand subtrees so you can focus on what you're looking for.

In addition, the ``ovs-flowviz datapath graph`` format generates a graphviz
graph definition where each block of flows with the same ``recirc_id`` match
are arranged together and edges are created to represent recirculations.
Also, this format comes with further goodies such as displaying the conntrack
zones which are key to understanding what the datapath is really doing with a
packet.

These two formats (``html`` and ``graph``) can even be combined. By using the
``ovs-flowviz datapath graph --html`` command, you'll get an interactive
HTML table alongside a `svg` graphical representation of the flows. Click on
a flow on the svg and it'll take you to the corresponding entry in the
flow table.


Filtering
~~~~~~~~~

Apart from being able to expand and collapse subtrees, we can use filtering.

However, filtering works in a slightly different way compared with OpenFlow
flows. Instead of just removing non-matching flows, the output
of a filtered datapath flow tree will show full sub-trees that contain at
least one flow that satisfies the filter.

For example, let's take the flows in the above example, and let's imagine we
want to understand what traffic is going out on port ``9``. We could run
the tool as:
::

   $ ovs-appctl dpctl/dump-flows | ovs-flowviz -f "output.port=9" datapath tree

The resulting flow tree will contain all of the flows above, even those
with ``recirc_id(0)`` and ``recirc_id(19348)`` that don't actually output
traffic to port ``9``. Why? because they are all part of a subtree that
contains flows that do output packets on port ``9``

That way, we see the "full picture" of how traffic on port ``9`` is being
processed.

.. _ovs-flowviz(8): https://docs.openvswitch.org/en/latest/ref/ovs-flowviz.8
