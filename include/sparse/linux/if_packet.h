#ifndef FIX_LINUX_IF_PACKET_H
#define FIX_LINUX_IF_PACKET_H

#ifndef __CHECKER__
#error "Use this header only with sparse.  It is not a correct implementation."
#endif

#include <openvswitch/types.h>
#include_next <linux/if_packet.h>

/* Fix endianness of 'spkt_protocol' and 'sll_protocol' members. */

#define sockaddr_pkt rpl_sockaddr_pkt
struct sockaddr_pkt {
        unsigned short spkt_family;
        unsigned char spkt_device[14];
        ovs_be16 spkt_protocol;
};

#define sockaddr_ll rpl_sockaddr_ll
struct sockaddr_ll {
        unsigned short  sll_family;
        ovs_be16        sll_protocol;
        int             sll_ifindex;
        unsigned short  sll_hatype;
        unsigned char   sll_pkttype;
        unsigned char   sll_halen;
        unsigned char   sll_addr[8];
};

/* Packet types */
#define PACKET_HOST                     0 /* To us                */
#define PACKET_OTHERHOST                3 /* To someone else 	*/
#define PACKET_LOOPBACK                 5 /* MC/BRD frame looped back */

/* Packet socket options */
#define PACKET_RX_RING                  5
#define PACKET_VERSION                 10
#define PACKET_TX_RING                 13
#define PACKET_VNET_HDR                15

/* Rx ring - header status */
#define TP_STATUS_KERNEL                0
#define TP_STATUS_USER            (1 << 0)
#define TP_STATUS_VLAN_VALID      (1 << 4) /* auxdata has valid tp_vlan_tci */
#define TP_STATUS_VLAN_TPID_VALID (1 << 6) /* auxdata has valid tp_vlan_tpid */

/* Tx ring - header status */
#define TP_STATUS_SEND_REQUEST    (1 << 0)
#define TP_STATUS_SENDING         (1 << 1)

#define tpacket_hdr rpl_tpacket_hdr
struct tpacket_hdr {
    unsigned long tp_status;
    unsigned int tp_len;
    unsigned int tp_snaplen;
    unsigned short tp_mac;
    unsigned short tp_net;
    unsigned int tp_sec;
    unsigned int tp_usec;
};

#define TPACKET_ALIGNMENT 16
#define TPACKET_ALIGN(x) (((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))

#define tpacket_hdr_variant1 rpl_tpacket_hdr_variant1
struct tpacket_hdr_variant1 {
    uint32_t tp_rxhash;
    uint32_t tp_vlan_tci;
    uint16_t tp_vlan_tpid;
    uint16_t tp_padding;
};

#define tpacket3_hdr rpl_tpacket3_hdr
struct tpacket3_hdr {
    uint32_t  tp_next_offset;
    uint32_t  tp_sec;
    uint32_t  tp_nsec;
    uint32_t  tp_snaplen;
    uint32_t  tp_len;
    uint32_t  tp_status;
    uint16_t  tp_mac;
    uint16_t  tp_net;
    /* pkt_hdr variants */
    union {
        struct tpacket_hdr_variant1 hv1;
    };
    uint8_t  tp_padding[8];
};

#define tpacket_bd_ts rpl_tpacket_bd_ts
struct tpacket_bd_ts {
    unsigned int ts_sec;
    union {
        unsigned int ts_usec;
        unsigned int ts_nsec;
    };
};

#define tpacket_hdr_v1 rpl_tpacket_hdr_v1
struct tpacket_hdr_v1 {
    uint32_t block_status;
    uint32_t num_pkts;
    uint32_t offset_to_first_pkt;
    uint32_t blk_len;
    uint64_t __attribute__((aligned(8))) seq_num;
    struct tpacket_bd_ts ts_first_pkt, ts_last_pkt;
};

#define tpacket_bd_header_u rpl_tpacket_bd_header_u
union tpacket_bd_header_u {
    struct tpacket_hdr_v1 bh1;
};

#define tpacket_block_desc rpl_tpacket_block_desc
struct tpacket_block_desc {
    uint32_t version;
    uint32_t offset_to_priv;
    union tpacket_bd_header_u hdr;
};

#define TPACKET3_HDRLEN \
    (TPACKET_ALIGN(sizeof(struct tpacket3_hdr)) + sizeof(struct sockaddr_ll))

enum rpl_tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3
};

#define tpacket_req3 rpl_tpacket_req3
struct tpacket_req3 {
    unsigned int tp_block_size; /* Minimal size of contiguous block */
    unsigned int tp_block_nr; /* Number of blocks */
    unsigned int tp_frame_size; /* Size of frame */
    unsigned int tp_frame_nr; /* Total number of frames */
    unsigned int tp_retire_blk_tov; /* Timeout in msecs */
    unsigned int tp_sizeof_priv; /* Offset to private data area */
    unsigned int tp_feature_req_word;
};
#endif
