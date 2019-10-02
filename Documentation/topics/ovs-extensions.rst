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

=======================
Open vSwitch Extensions
=======================

Introduction
------------
OpenFlow since version 1.0 allows vendor extensions to be added in the
protocol and OVS has used these extensions in the implementation. (Initially
also known as 'Nicira extensions'. This is the reason we see the prefix
'NX' in the different vendor extension messages.)
These extensions have been used to add additional functionality for the
desired features not present in the standard OpenFlow protocol.


OVS vendor extension messages in OpenFlow and OVS
-------------------------------------------------

1. **OFPT_VENDOR (In OpenFlow 1.0) or
   OFPT_EXPERIMENTER (In OpenFlow 1.1+)**

This is a vendor message type with value the value of OFPT_VENDOR
or OFPT_EXPERIMENTER (refer to respective OpenFlow specifications)
in the OpenFlow header 'type' field. After the header of this message,
there is a vendor id field which identifies the vendor. This is followed
by a subtype field which defines the vendor specific message types.
The vendor ids are defined in: ovs/include/openflow/openflow-common.h

To see a list of all the vendor message subtypes, we
can refer to 'ovs/lib/ofp-msgs.h' file. We can see the instances
of 'ofpraw' enum which has a comment containing the keyword NXT.
For e.g. in the below mentioned line containing OFPRAW_NXT_FLOW_MOD:

::

   /* NXT 1.0+ (13): struct nx_flow_mod, uint8_t[8][]. */
   OFPRAW_NXT_FLOW_MOD,

   NXT          - stands for Nicira extension message.
   nx_flow_mod  - data that follow the OpenFlow header.
   uint8_t[8][] - multiple of 8 data.
   13           - is the subtype for the Flow Mod message when it is sent as a
                 Open vSwitch extension message.
   OFPRAW_NXT_FLOW_MOD - is the Open vSwitch Flow Mod extension message.


For reference, the vendor message header is defined as
'struct ofp_vendor_header' in 'ovs/lib/ofp-msgs.c'.

The general structure of a message with a vendor message type is:

ofp_header(msg_type=VENDOR/EXPERIMENTER) / vendor id / vendor subtype /
vendor defined additional data
(e.g. nx_flow_mod structure for OFPRAW_NXT_FLOW_MOD message)


2. **OFPST_VENDOR (In OpenFlow 1.0) or
   OFPST_EXPERIMENTER (In OpenFlow 1.1 and 1.2) or
   OFPMP_EXPERIMENTER (In OpenFlow 1.3+):**

The OpenFlow message type OFPT_STATS_REQUEST/OFPT_STATS_REPLY or
OFPT_MULTIPART_REQUEST/OFPT_MULTIPART_REPLY defines the above VENDOR or
EXPERIMENTER multipart type in the message.

Again if we refer to 'ovs/lib/ofp-msgs.h', we see the following lines:

::

    /* NXST 1.0 (2): uint8_t[8][]. */
    OFPRAW_NXST_FLOW_MONITOR_REQUEST,


    NXST         - stands for Nicira extension statistics or multipart message.
    uint8_t[8][] - multiple of 8 data.
    2            - is the subtype for the Flow Monitor Request message when it
            is sent as a Flow Monitor Request message with extension vendor id.
    OFPRAW_NXST_FLOW_MONITOR_REQUEST - is the OpenFlow Flow Monitor extension
    message.

For reference, the vendor extension stats message header is defined as
'struct ofp11_vendor_stats_msg' in 'ovs/lib/ofp-msgs.c'.

The general structure of a multipart/stats message with vendor type is:

ofp_header(msg_type=STATS/MULTIPART) / stats_msg(type=VENDOR/EXPERIMENTER) /
 vendor-id / subtype / vendor defined additional data


Extended Match
--------------

NXM (Nicira Extended Match) is used to extend the flow
match structure. OpenFlow 1.0 uses a fixed size flow match structure
(struct ofp_match) to define the fields to match in a packet.
This is limiting and not extensible.
To make the match structure extensible, OVS added as an extension
'nx_match' structure which are a series of TLV (type-length-value) entries or
'nxm_entry's.

For a detailed description of NXM, please see the OVS fields documentation
at: http://openvswitch.org/support/dist-docs/ovs-fields.7.txt

Error Message Extension
-----------------------

In the OpenFlow version 1.0 and 1.1, there is no provision to generate
vendor specific error codes and does not even provide 'generic' error
codes that can apply to problems not anticipated by the OpenFlow
specification authors. OVS added a generic "error vendor
extension" which uses NXET_VENDOR as type and NXVC_VENDOR_ERROR as code,
followed by struct 'nx_vendor_error' with vendor-specific details,
followed by at least 64 bytes of the failed request.

Later, OpenFlow version 1.2+ added a 'OFPET_EXPERIMENTER' error type to
generate vendor specific error codes.

Source files related to Open vSwitch extensions
-----------------------------------------------

::

   ovs/include/openflow/nicira-ext.h
   ovs/lib/ofp-msgs.inc
   ovs/include/openvswitch/ofp-msgs.h
   ovs/lib/ofp-msgs.c
