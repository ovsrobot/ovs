#!/usr/bin/env python3
from bcc import BPF, USDT, USDTException

import argparse
import psutil
import sys
import time
from scapy.all import hexdump, wrpcap
from scapy.layers.l2 import Ether
import struct


bpf_src = """
#include <linux/sched.h>
#include <linux/types.h>
#include <uapi/linux/ptrace.h>

#define MAX_KEY     2048

struct flow_put {
    u32 flags;
    u64 key_ptr;
    u64 key_len;
    u64 mask_ptr;
    u64 mask_len;
    u64 action_ptr;
    u64 action_len;
    u64 ufid_loc;
};
struct event_t {
    u64 ts;
    u32 reason;
    u32 ufid[4];
    u64 key_size;
    unsigned char key[MAX_KEY];
};

BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_COUNT>);

int watch_reval(struct pt_regs *ctx) {
    uint64_t addr;
    struct event_t *data = events.ringbuf_reserve(sizeof(struct event_t));
    if(!data)
        return 1;
    data->ts = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &data->reason);
    bpf_usdt_readarg(2, ctx, &addr);
    bpf_probe_read(&data->ufid,sizeof(data->ufid),(void *)addr);
    events.ringbuf_submit(data, 0);
    return 0;
};


int watch_put(struct pt_regs *ctx) {
    uint64_t addr;
    struct event_t *data = events.ringbuf_reserve(sizeof(struct event_t));
    struct flow_put f;
    if(!data)
        return 1;
    data->ts = bpf_ktime_get_ns();
    bpf_usdt_readarg(2, ctx, &addr);
    bpf_probe_read(&f, sizeof(struct flow_put), (void *) addr);
    bpf_probe_read(&data->ufid, sizeof(data->ufid),(void *) f.ufid_loc);
    if (f.key_len > MAX_KEY) // verifier fails without this check.
        f.key_len = MAX_KEY;
    data->key_size = f.key_len;
    bpf_probe_read(&data->key, f.key_len,(void*)f.key_ptr);
    data->reason = 0;
    events.ringbuf_submit(data, 0);
    return 0;
};
"""

def format_ufid(ufid):
    result = "ufid:%08x-%04x-%04x-%04x-%04x%08x" \
    % (ufid[0],
    ufid[1] >> 16,
    ufid[1] & 0xffff,
    ufid[2] >> 16,
    ufid[2] & 0,
    ufid[3])
    return result

def print_flow_put(event):
    ufid_str = format_ufid(event.ufid)
    print("At time: {:<18.9f} a flow with ufid: {} was upcalled".
        format(event.ts / 1000000000,ufid_str))
    key = decode_key(bytes(event.key)[:event.key_size])
    if args.filter_flows:
        if "OVS_KEY_ATTR_IPV4" in key:
            print("Found an ipv4 flow. Adding its ufid to the watchlist")
            ufids.append(ufid_str)

def print_expiration(event):
    ufid_str = format_ufid(event.ufid)
    reason_code = ""
    if args.filter_flows:
        if ufid_str not in ufids:
            return
        else:
            print("A tracked flow is expiring")
    if event.reason == 1:
        reason_code = "flow timed out"
    elif event.reason == 2:
        reason_code = "flow was too expensive to revalidate"
    elif event.reason == 3:
        reason_code = "flow was wildcarded"
    elif event.reason == 4:
        reason_code = "bad odp fit"
    elif event.reason == 5:
        reason_code = "associated ofproto"
    elif event.reason == 6:
        reason_code = "translation error"
    elif event.reason == 7:
        reason_code = "avoid_caching"
    print("At time: {:<18.9f} a flow with ufid: {} was deleted for reason: {}".
        format(event.ts / 1000000000, ufid_str, reason_code))

def decode_key(msg,dump=True):
    dump=args.print_flow_keys
    bytes_left = len(msg)
    result = {}
    while bytes_left:
        if bytes_left < 4:
            if dump:
                print("{}WARN: decode truncated; cannot read header".format(
                    ' ' * 4))
            break
        nla_len, nla_type = struct.unpack("=HH", msg[:4])
        if nla_len < 4:
            if dump:
                print("{}WARN: decode truncated; nla_len < 4".format(' ' * 4))
            break
        nla_data = msg[4:nla_len]
        trunc = ""
        if nla_len > bytes_left:
            trunc = "..."
            nla_data = nla_data[:(bytes_left - 4)]
        else:
            result[get_ovs_key_attr_str(nla_type)] = nla_data
        if dump:
            print("{}nla_len {}, nla_type {}[{}], data: {}{}".format(
                ' ' * 4, nla_len, get_ovs_key_attr_str(nla_type),
                nla_type,
                "".join("{:02x} ".format(b) for b in nla_data), trunc))
        if trunc != "":
            if dump:
                print("{}WARN: decode truncated; nla_len > msg_len[{}] ".
                      format(" " * 4, bytes_left))
            break
        next_offset = (nla_len + 3) & (~3)
        msg = msg[next_offset:]
        bytes_left -= next_offset
    return result

def get_ovs_key_attr_str(attr):
    ovs_key_attr = ["OVS_KEY_ATTR_UNSPEC",
                    "OVS_KEY_ATTR_ENCAP",
                    "OVS_KEY_ATTR_PRIORITY",
                    "OVS_KEY_ATTR_IN_PORT",
                    "OVS_KEY_ATTR_ETHERNET",
                    "OVS_KEY_ATTR_VLAN",
                    "OVS_KEY_ATTR_ETHERTYPE",
                    "OVS_KEY_ATTR_IPV4",
                    "OVS_KEY_ATTR_IPV6",
                    "OVS_KEY_ATTR_TCP",
                    "OVS_KEY_ATTR_UDP",
                    "OVS_KEY_ATTR_ICMP",
                    "OVS_KEY_ATTR_ICMPV6",
                    "OVS_KEY_ATTR_ARP",
                    "OVS_KEY_ATTR_ND",
                    "OVS_KEY_ATTR_SKB_MARK",
                    "OVS_KEY_ATTR_TUNNEL",
                    "OVS_KEY_ATTR_SCTP",
                    "OVS_KEY_ATTR_TCP_FLAGS",
                    "OVS_KEY_ATTR_DP_HASH",
                    "OVS_KEY_ATTR_RECIRC_ID",
                    "OVS_KEY_ATTR_MPLS",
                    "OVS_KEY_ATTR_CT_STATE",
                    "OVS_KEY_ATTR_CT_ZONE",
                    "OVS_KEY_ATTR_CT_MARK",
                    "OVS_KEY_ATTR_CT_LABELS",
                    "OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4",
                    "OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6",
                    "OVS_KEY_ATTR_NSH"]
    if attr < 0 or attr > len(ovs_key_attr):
        return "<UNKNOWN>"
    return ovs_key_attr[attr]

def handle_event(ctx,data,size):
    event = b["events"].event(data)
    if event.reason == 0:
        print_flow_put(event)
    else:
        print_expiration(event)

def main():
    global b
    global ufids
    global args
    ufids = []
    parser = argparse.ArgumentParser()
    parser.add_argument("--buffer-page-count",
                        help="Number of BPF ring buffer pages, default 1024",
                        type=int, default=1024, metavar="NUMBER")
    parser.add_argument("-k", "--print-flow-keys",
                        help="Print flow keys captured?",
                        type=bool, const=True,default=False,nargs="?")
    parser.add_argument("--pid","-p",metavar="VSWITCHD_PID",
                        help="ovs-vswitchd's PID", type=int, default=None)
    parser.add_argument("--mask", "-m", metavar="FLOW_MASK",
                        help="flow mask to match",nargs=1,type=int,default=None)
    parser.add_argument("-D", "--debug", help="debug eBPF",
                        type=int, const=0x3f, default=0, nargs="?")
    parser.add_argument("-F", "--filter-flows",
                        help="Filter flows based on conditions (to implement)",
                        type=bool, const=True,default=False, nargs="?")
    args = parser.parse_args()
    vswitch_pid = args.pid
    if vswitch_pid is None:
        for proc in psutil.process_iter():
            if "ovs-vswitchd" in proc.name():
                if vswitch_pid is not None:
                    print("Error: Multiple ovs-vswitchd daemons running. "
                          "Use the -p option to specify one to track.")
                    sys.exit(-1)
                vswitch_pid = proc.pid
    if vswitch_pid is None:
        print("Error: is ovs-vswitchd running?")
        sys.exit(-1)
    if args.mask is not None:
        print("mask is: ")
    u = USDT(pid=int(vswitch_pid))
    try:
        u.enable_probe(probe="op_flow_put", fn_name="watch_put")
    except USDTException as e:
        print("Error attaching flow_put probe.")
        print(str(e))
        sys.exit(-1)
    try:
        u.enable_probe(probe="flow_delete", fn_name="watch_reval")
    except USDTException as e:
        print("Error attaching revalidator_deletion probe.")
        print(str(e))
        sys.exit(-1)

    source = bpf_src.replace("<BUFFER_PAGE_COUNT>",
                            str(args.buffer_page_count))
    b = BPF(text=source, usdt_contexts=[u],debug=args.debug)
    b["events"].open_ring_buffer(handle_event)
    print("Watching for events")
    while 1:
        try:
            b.ring_buffer_poll()
            time.sleep(0.5)
        except KeyboardInterrupt:
            break




if __name__ == "__main__":
    main()
