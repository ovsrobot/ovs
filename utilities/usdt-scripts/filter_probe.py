#!/usr/bin/env python3
from bcc import BPF
from bcc import USDT
from bcc import USDTException

import argparse
import psutil
import struct
import sys
import time

#
# eBPF source code
#
bpf_src = """
#include <linux/sched.h>
#include <linux/types.h>
#include <uapi/linux/ptrace.h>

#define MAX_KEY     2048
#define FLOW_FILTER  <FILTER_BOOL>


enum probe { PUT, REVAL };
union u_ufid {
    u32 ufid32[4];
    u64 ufid64[2];
};
struct netlink_attr {
    u16 len;
    u16 type;
};
struct flow_put {
    int flags;
    u64 key_ptr;
    size_t key_len;
    u64 mask_ptr;
    size_t mask_len;
    u64 action_ptr;
    size_t action_len;
    u64 ufid_loc;
};
struct ukey {
    u64 cmap_node; // ???????????????????? maybe?
    u64 key_ptr;
    u64 key_len;
    u64 mask_ptr;
    u64 mask_len;
    union u_ufid ufid;
};

struct event_t {
    u64 ts;
    u32 reason;
    u32 ufid[4];
    u64 key_size;
    unsigned char key[MAX_KEY];
    enum probe probe;
};

BPF_HASH(watchlist, union u_ufid);
BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_COUNT>);

int watch_reval(struct pt_regs *ctx) {
    u64 *ufid_present = NULL;
    struct ukey u;
    bpf_usdt_readarg_p(3, ctx, &u, sizeof(struct ukey));
    union u_ufid ufid = u.ufid;
    ufid_present = watchlist.lookup(&ufid);
    if(FLOW_FILTER && !ufid_present)
        return 0; // return, since this is not the droid we're looking for.
    struct event_t *data = events.ringbuf_reserve(sizeof(struct event_t));
    /* If we can't reserve the space we need for the ring buffer, return 1 */
    if(!data)
        return 1;
    data->probe = REVAL;
    data->ts = bpf_ktime_get_ns();
    bpf_probe_read(&data->ufid, sizeof(ufid), &ufid);
    bpf_usdt_readarg(1, ctx, &data->reason);
    events.ringbuf_submit(data, 0);
    return 0;
};


int watch_put(struct pt_regs *ctx) {
    struct event_t *data = events.ringbuf_reserve(sizeof(struct event_t));
    struct flow_put f;
    struct netlink_attr nla;
    union u_ufid ufid;
    if(!data)
        return 1;
    data->probe = PUT;
    data->ts = bpf_ktime_get_ns();
    bpf_usdt_readarg_p(2, ctx, &f, sizeof(struct flow_put));
    bpf_probe_read(&data->ufid, sizeof(data->ufid), (void *) f.ufid_loc);
    bpf_probe_read(&ufid, sizeof(ufid), &data->ufid); // maybe a better way?
    if (f.key_len > MAX_KEY) // verifier fails without this check.
        f.key_len = MAX_KEY;
    data->key_size = f.key_len;
    bpf_probe_read(&data->key, f.key_len, (void*)f.key_ptr);
    watchlist.increment(ufid);
    data->reason = 0;
    events.ringbuf_submit(data, 0);
    return 0;
};
"""


def format_ufid(ufid):
    result = "ufid:%08x-%04x-%04x-%04x-%04x%08x" \
             % (ufid[0], ufid[1] >> 16, ufid[1] & 0xffff,
                ufid[2] >> 16, ufid[2] & 0, ufid[3])
    return result


def find_and_delete_from_watchlist(event):
    for k, _ in b['watchlist'].items():
        key_ufid = struct.unpack("=IIII", k)
        if key_ufid == tuple(event.ufid):
            key = (b['watchlist'].Key * 1)(k)
            b['watchlist'].items_delete_batch(key)
            break


def handle_flow_put(event):
    if args.filter_flows is not None:
        key = decode_key(bytes(event.key)[:event.key_size])
        # for each attribute that we're watching
        for attr in target:
            # if that attribute isn't in our current key
            if attr not in key:
                # find and delete matching key
                find_and_delete_from_watchlist(event)
                return
    print("At time: {:<18.9f} a flow with ufid: {} was upcalled".
          format(event.ts / 1000000000, format_ufid(event.ufid)))


def print_expiration(event):
    ufid_str = format_ufid(event.ufid)
    reasons = ["flow timed out", "flow was too expensive",
               "flow wildcards", "bad odp fit", "associated ofproto",
               "translation error", "cache avoidance", "ERR"]
    print("At time: {:<18.9f} a flow with ufid: {} was deleted for reason: {}".
          format(event.ts / 1000000000, ufid_str, reasons[event.reason - 1]))


def decode_key(msg, dump=True):
    dump = args.print_flow_keys
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


def handle_event(ctx, data, size):
    """Determine the probe event and what to do about it.

    Once we grab the event, we have three cases.
    1. It's a revalidator probe and the reason is nonzero: A flow is expiring
    2. It's a revalidator probe and the reason is zero: flow revalidated
    3. It's a flow_put probe.
    """
    event = b["events"].event(data)
    if event.probe and event.reason:
        print_expiration(event)
    if not event.probe:
        handle_flow_put(event)


def main():
    global b
    global args
    # TODO(Kevin Sprague): Parser for user input flow attribute.
    global target
    target = ["OVS_KEY_ATTR_IPV4"]
    parser = argparse.ArgumentParser()
    parser.add_argument("--buffer-page-count",
                        help="Number of BPF ring buffer pages, default 1024",
                        type=int, default=1024, metavar="NUMBER")
    parser.add_argument("-k", "--print-flow-keys",
                        help="Print flow keys captured?",
                        type=bool, const=True, default=False, nargs="?")
    parser.add_argument("--pid", "-p", metavar="VSWITCHD_PID",
                        help="ovs-vswitchd's PID", type=int, default=None)
    parser.add_argument("-D", "--debug", help="debug eBPF",
                        type=int, const=0x3f, default=0, nargs="?")
    # right now, this is active if given a string, but it does nothing with
    # with the string. This should pass into a function that turns it to a list
    # of attributes
    parser.add_argument("-f", "--filter-flows",
                        help="Filter flows based on conditions (to implement)",
                        type=str, default=None, nargs="*")
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
    u = USDT(pid=int(vswitch_pid))
    try:
        u.enable_probe(probe="op_flow_put", fn_name="watch_put")
    except USDTException as e:
        print("Error attaching flow_put probe.")
        print(str(e))
        sys.exit(-1)
    try:
        u.enable_probe(probe="flow_results", fn_name="watch_reval")
    except USDTException as e:
        print("Error attaching revalidator_deletion probe.")
        print(str(e))
        sys.exit(-1)
    filter_bool = 1 if args.filter_flows is not None else 0
    source = bpf_src.replace("<BUFFER_PAGE_COUNT>",
                             str(args.buffer_page_count))
    source = source.replace("<FILTER_BOOL>", str(filter_bool))
    b = BPF(text=source, usdt_contexts=[u], debug=args.debug)
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
