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

=====================
OVS Nicira Extensions
=====================

Q: What are the Nicira vendor messages in OpenFlow and OVS?

    A: OpenFlow since version 1.0 allows 'vendor objects' to be added in the
    protocol and OVS has used this as 'Nicira extensions' in the
    implementation. It has been used to add additional functionality for
    the desired features not present in the standard OpenFlow protocol.

    There are two types of vendor or experimenter message types in OpenFlow:


    1. **OFPT_VENDOR (In OpenFlow 1.0) or
       OFPT_EXPERIMENTER (In OpenFlow 1.1+)**

    This is a vendor message type with value the value of 4
    in the OpenFlow header 'type' field. After the header of this message,
    there is a vendor id field which identifies the vendor. This is followed
    by a subtype field which defines the vendor specific message types.
    Currently, following vendor ids are defined:

    (ovs/include/openflow/openflow-common.h)

    ::

       HPL_VENDOR_ID          0x000004EA  HP Labs
       NTR_VENDOR_ID          0x0000154d  Netronome
       NTR_COMPAT_VENDOR_ID   0x00001540  Incorrect value used in v2.4
       NX_VENDOR_ID           0x00002320  Nicira
       ONF_VENDOR_ID          0x4f4e4600  Open Networking Foundation
       INTEL_VENDOR_ID        0x0000AA01  Intel

    OVS uses the Nicira vendor id 0x00002320 for all the vendor extension
    messages. To see a list of all the Nicira vendor message subytes, we
    can refer to 'ovs/lib/ofp-msgs.inc' file which gets auto generated after
    compiling the ovs code. Here we can see all the structures of type
    'struct raw_instance' and check for lines containing the hex string
    0x2320. For e.g. in the following line inside
    'ofpraw_nxt_flow_mod_instances':

    ::

       { {0, NULL}, {1, 4, 0, 0x2320, 13}, OFPRAW_NXT_FLOW_MOD, 0 },

       1      -  is the OpenFlow version 1
       4      -  is the vendor/experimenter message type
       0x2320 -  the the Nicira vendor id
       13     -  is the subtype for the Flow Mod message when it is sent as a
                 Nicira extended message

    Following the above line, we also see a set of following lines:

    ::

        { {0, NULL}, {2, 4, 0, 0x2320, 13}, OFPRAW_NXT_FLOW_MOD, 0 },
        { {0, NULL}, {3, 4, 0, 0x2320, 13}, OFPRAW_NXT_FLOW_MOD, 0 },
        { {0, NULL}, {4, 4, 0, 0x2320, 13}, OFPRAW_NXT_FLOW_MOD, 0 },
        { {0, NULL}, {5, 4, 0, 0x2320, 13}, OFPRAW_NXT_FLOW_MOD, 0 },
        { {0, NULL}, {6, 4, 0, 0x2320, 13}, OFPRAW_NXT_FLOW_MOD, 0 },

    Here, only the OpenFlow version is changing (from 2 to 6). This means that
    the OFPRAW_NXT_FLOW_MOD Nicira extension message is supported in all the
    OpenFlow versions from 1 to 6.

    On the other hand, we have the vendor OFPRAW_NXT_GROUP_MOD Nicira
    extension message:

    ::

        static struct raw_instance ofpraw_nxt_group_mod_instances[] = {
            { {0, NULL}, {1, 4, 0, 0x2320, 31}, OFPRAW_NXT_GROUP_MOD, 0 },
        };

    which does not have lines corresponding to versions 2 to 6 i.e. the group
    mod Nicira vendor extension message (subtype 31) is only supported in
    OpenFlow version 1.

    For reference, the vendor message header is defined as:

    ::

        /* ofp-msgs.c */
        /* Vendor extension message. */
        struct ofp_vendor_header {
            struct ofp_header header; /* OFPT_VENDOR. */
            ovs_be32 vendor;          /* Vendor ID:
                                       * - MSB 0: low-order bytes are IEEE OUI.
                                       * - MSB != 0: defined by OpenFlow
                                       *   consortium. */

            /* In theory everything after 'vendor' is vendor specific. In
             * practice, the vendors we support put a 32-bit subtype here.
             * We'll change this structure if we start adding support for
             * other vendor formats. */
            ovs_be32 subtype;           /* Vendor-specific subtype. */

            /* Followed by vendor-defined additional data. */
        };
        OFP_ASSERT(sizeof(struct ofp_vendor_header) == 16);

    2. **OFPST_VENDOR (In OpenFlow 1.0) or
       OFPST_EXPERIMENTER (In OpenFlow 1.1 and 1.2) or
       OFPMP_EXPERIMENTER (In OpenFlow 1.3+):**

    The OpenFlow message type OFPT_STATS_REQUEST/OFPT_STATS_REPLY or
    OFPT_MULTIPART_REQUEST/OFPT_MULTIPART_REPLY defines the above VENDOR or
    EXPERIMENTER multipart type in the message.

    Again if we refer to 'ovs/lib/ofp-msgs.inc', we see the following lines:

    ::

        static struct
                 raw_instance ofpraw_nxst_flow_monitor_request_instances[] = {
            { {0, NULL}, {1, 16, 65535, 0x2320, 2},
                                     OFPRAW_NXST_FLOW_MONITOR_REQUEST, 0 },
        };

        1       - is the OpenFlow version 1
        16      - is the OpenFlow message type OFPT_STATS_REQUEST
        65535   - is the OFPST_VENDOR/OFPST_EXPERIMENTER/OFPMP_EXPERIMENTER
                  stats/multipart type 0xffff
        0x2320  - the the Nicira vendor id
        2       - is the subtype for the Flow Monitor Request message when it
                  is sent as a Stats Request message with Nicira vendor id

    OFPRAW_NXST_FLOW_MONITOR_REQUEST is not supported in OpenFlow
    versions 2 to 6 as there are no lines corresponding to those versions.

    For reference, the vendor extension stats message header is defined as:

    ::

        /* ofp-msgs.c */
        /* Vendor extension stats message. */
        struct ofp11_vendor_stats_msg {
            struct ofp11_stats_msg osm;/* Type OFPST_VENDOR. */
            ovs_be32 vendor;           /* Vendor ID:
                                        * - MSB 0: low-order bytes are IEEE OUI
                                        * - MSB != 0: defined by OpenFlow
                                        *   consortium. */

            /* In theory everything after 'vendor' is vendor specific.
             * In practice, the vendors we support put a 32-bit subtype here.
             * We'll change this structure if we start adding support for other
             * vendor formats. */
            ovs_be32 subtype;           /* Vendor-specific subtype. */

            /* Followed by vendor-defined additional data. */
        };
        OFP_ASSERT(sizeof(struct ofp11_vendor_stats_msg) == 24);

        /* Header for Nicira vendor stats request and reply messages in
         * OpenFlow 1.0. */
        struct nicira10_stats_msg {
            struct ofp10_vendor_stats_msg vsm; /* Vendor NX_VENDOR_ID. */
            ovs_be32 subtype;           /* One of NXST_* below. */
            uint8_t pad[4];             /* Align to 64-bits. */
        };
        OFP_ASSERT(sizeof(struct nicira10_stats_msg) == 24);



Q: What is NXM?

    A: NXM stands for *Nicira Extended Match* which is used to extend the flow
    match structure. OpenFlow 1.0 uses a fixed size flow match structure
    (struct ofp_match) to define the fields to match in a packet.
    This is limiting and not
    extensible. To make the match structure extensible, Nicira added the NXM
    or 'nx_match' which are a series of TLV (type-length-value) entries or
    'nxm_entry's. The first four bytes of 'nxm_entry' are it's header followed
    by the body.

    An nxm_entry's header is interpreted as a 32-bit word in network byte
    order:

    ::

     |<-------------------- nxm_type ------------------>|
     |                                                  |
     |31                              16 15            9| 8 7                0
     +----------------------------------+---------------+--+------------------+
     |            nxm_vendor            |   nxm_field   |hm|    nxm_length    |
     +----------------------------------+---------------+--+------------------+

    'nxm_vendor' field would be OFPXMC12_NXM_0 or OFPXMC12_NXM_1 when the
    'nxm_field' is a Nicira field.

    'nx_match' is used in Nicira vendor messages 'nx_packet_in',
    'nx_flow_mod, 'nx_flow_removed', 'nx_flow_stats_request', 'nx_flow_stats',
    'nx_aggregate_stats_request', 'nx_flow_monitor_request' and
    'nx_flow_update_full'.

    In OpenFlow 1.1, the 'struct ofp_match' match structure was modified in an
    attempt to make it future extensible by adding a 'type' field with a note
    in the specification that if the match needs to be extended, these fields
    may be modified.

    Eventually, after OpenFlow version 1.2+ the 'struct ofp_match' has a type
    'OFPMT_OXM' (or OpenFlow Extensible Match) which is match structure
    containing a series of TLV (type-length-value) entries very similar
    to NXM. The OXM TLV header is exactly same as nxm_entry header:

    ::

     +----------------------------------+---------------+--+------------------+
     |            oxm_class             |   oxm_field   |hm|    oxm_length    |
     +----------------------------------+---------------+--+------------------+

    The oxm_class value of OFPXMC_NXM_0 or OFPXMC_NXM_1 can be used an
    OpenFlow 1.2+ message to use a Nicira 'nxm_field' otherwise standard
    OpenFlow fields are used when the oxm_class has a value of
    OFPXMC_OPENFLOW_BASIC.

    Interestingly OVS in ovs-ofctl can use the value of OFPXMC_OPENFLOW_BASIC
    for 'nxm_vendor' in an OpenFlow 1.0 message in a 'nx_match' TLV when
    encoding a match field not supported in OpenFlow 1.0.
    (e.g. 'sctp_src' is not supported by OpenFlow 1.0 and does not have a NXM
    type field but can still be used in OpenFlow 1.0 with the 'nxm_vendor'
    type as OFPXMC_OPENFLOW_BASIC and oxm_field of type
    OXM_OF_SCTP_SRC as a backward compatible support)


Q: What are the other Nicira 'vendor objects' in OVS?

    A: *Vendor error type/code* - In the OpenFlow version 1.0 and 1.1,
    there is no provision to generate
    vendor specific error codes and does not even provide 'generic' error
    codes that can apply to problems not anticipated by the OpenFlow
    specification authors. Nicira extension added a generic "error vendor
    extension" which uses NXET_VENDOR as type and NXVC_VENDOR_ERROR as code,
    followed by struct 'nx_vendor_error' with vendor-specific details,
    followed by at least 64 bytes of the failed request.

    OpenFlow version 1.2+ added a 'OFPET_EXPERIMENTER' error type to generate
    vendor specific error codes.

Q: Where can I find the files related to Nicira vendor messages and other
vendor objects?

    A:

    ::

       ovs/include/openflow/nicira-ext.h
       ovs/lib/ofp-msgs.inc
       ovs/include/openvswitch/ofp-msgs.h
       ovs/lib/ofp-msgs.c
