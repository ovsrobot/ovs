#!/usr/bin/env python3
#
# Copyright (c) 2021 Red Hat, Inc.
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
#
# Script information:
# -------------------
# upcall_cost.py uses various user space and kernel space probes to determine
# the costs (in time) for handling the first packet in user space. It
# calculates the following costs:
#
# - Time it takes from the kernel sending the upcall till it's received by the
#   ovs-vswitchd process.
# - Time it takes from ovs-vswitchd sending the execute actions command till
#   the kernel receives it.
# - The total time it takes from the kernel to sent the upcall until it
#   receives the packet execute command.
# - The total time of the above, minus the time it takes for the actual lookup.
#
# In addition, it will also report the number of packets batched, as OVS will
# first try to read UPCALL_MAX_BATCH(64) packets from kernel space and then
# does the flow lookups and execution. So the smaller the batch size, the more
# realistic are the cost estimates.
#
# The script does not need any options to attach to a running instance of
# ovs-vswitchd. However, it's recommended always run the script with the
# --write-events option. This way, if something does go wrong, the collected
# data is saved. Use the --help option to see all the available options.
#
# Note: In addition to the bcc tools for your specific setup, you need the
#       following Python packages:
#         pip install alive-progress halo psutil scapy strenum text_histogram3
#

try:
    from bcc import BPF, USDT, USDTException
except ModuleNotFoundError:
    print("WARNING: Can't find the BPF Compiler Collection (BCC) tools!")
    print(
        "         This is NOT problem if you analyzing previously collected"
        " data.\n"
    )
from alive_progress import alive_bar
from collections import namedtuple
from ctypes import c_uint32
from halo import Halo
from itertools import chain
from os import listdir
from os.path import join, isdir
from scapy.layers.l2 import Ether
from strenum import StrEnum
from text_histogram3 import histogram
from time import process_time

import argparse
import ast
import psutil
import re
import struct
import subprocess
import sys
import time

#
# Global definitions
#
DP_TUNNEL_PORT = -1


#
# Actual eBPF source code
#
ebpf_source = """
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <uapi/linux/bpf.h>
#include <linux/jhash.h>

#define MAX_PACKET <MAX_PACKET_VAL>
#define MAX_KEY    <MAX_KEY_VAL>
#define PACKET_HASH_SIZE <PACKET_HASH_SIZE>
#define UPCALL_MAX_BATCH <UPCALL_MAX_BATCH>
#define MAX_HANDLERS <MAX_HANDLERS>

enum {
    EVENT_RECV_UPCALL = 0,
    EVENT_DP_UPCALL,
    EVENT_DP_UPCALL_QUEUE,
    EVENT_OP_FLOW_PUT,
    EVENT_OP_FLOW_EXECUTE,
    EVENT_OVS_PKT_EXEC,
    _EVENT_MAX_EVENT
};

#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

struct event_t {
    u32 event;
    u32 cpu;
    u32 pid;
    u64 ts;
    u32 upcall_id;
    u32 queue_id;
    u64 batch_ts;
    u32 pkt_frag_size;
    u32 pkt_size;
    u64 key_size;
    u8 batch_idx;
    int res;
    char comm[TASK_COMM_LEN];
    char dpif_name[32];
    char dev_name[16];
    unsigned char pkt[MAX_PACKET];
    unsigned char key[MAX_KEY];
};

/* Common (both kernel and userspace) maps. */
/* Output ring buffer for generated events. */
BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_CNT>);

/* Per-cpu array for dropcount. */
BPF_TABLE("percpu_array", uint32_t, uint64_t, dropcnt, _EVENT_MAX_EVENT);

/* Packet data to be used to for hashing.
 * Stack size is limted in ebpf programs, so we use a per-cpu array to store
 * the data we need to perform the packet hash. */
struct packet_buffer {
    unsigned char data[PACKET_HASH_SIZE];
};
BPF_PERCPU_ARRAY(packet_buffers, struct packet_buffer, 1);

/* Hash map used to store queue_ids of the in-flight execution actions. */
BPF_HASH(in_flight_exec, uint32_t, uint32_t);

static void dropcnt_inc(u32 type)
{
    dropcnt.increment(type);
}

static struct event_t *init_event(u32 type)
{
    struct event_t *event = events.ringbuf_reserve(sizeof(struct event_t));

    if (!event) {
        dropcnt_inc(type);
        return NULL;
    }

    event->event = type;
    event->ts = bpf_ktime_get_ns();
    event->cpu =  bpf_get_smp_processor_id();
    event->pid = bpf_get_current_pid_tgid();
    event->queue_id = 0;
    event->upcall_id = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    return event;
}

static uint32_t hash_packet(struct packet_buffer *buff,
                            void* pkt_data, uint64_t size, uint32_t init)
{
    memset(buff->data, 0, sizeof(buff->data));
    /* Prevent clang from using register mirroring (or any optimization) on
     * the 'size' variable. */
    barrier_var(size);
    if (size >= PACKET_HASH_SIZE) {
        bpf_probe_read(buff->data, PACKET_HASH_SIZE, pkt_data);
    } else {
        bpf_probe_read(buff->data, size, pkt_data);
    }
    return jhash(buff->data, PACKET_HASH_SIZE, init);
}

static uint32_t hash_skb(struct packet_buffer *buff,
                         struct sk_buff *skb, uint32_t init)
{
    if (!skb) {
        return 0;
    }
    uint64_t size;
    if (skb->data_len != 0) {
        size = (skb->len - skb->data_len) & 0xfffffff;
    } else {
        size = skb->len;
    }
    return hash_packet(buff, skb->data, size, init);
}

/* Kernel side. */

/* In fight upcall queuing storage.
 * The skb get's modified during execution of queue_userspace_packet before
 * they are sent to userspace. In order to get the right hash we need to
 * perform it when the function exists.
 * We do this by pairing a kprobe and a kretprobe. Unfortunately arguments are
 * not available in kretprobes so we store the needed arguments in a
 * hashmap. */
BPF_HASH(queue_args, uint32_t, struct sk_buff *);
/* In fight upcall id. Indexed by pid. */
BPF_HASH(upcalls, uint32_t, uint32_t);

struct datapath;
struct dp_upcall_info;
struct ip_tunnel_info;
struct nlattr;
struct pt_regs;
struct sk_buff;
struct sw_flow_key;
struct dp_upcall_info {
    struct ip_tunnel_info *egress_tun_info;
    const struct nlattr *userdata;
    const struct nlattr *actions;
    int actions_len;
    u32 portid;
    u8 cmd;
    u16 mru;
};

enum ovs_packet_cmd {
    OVS_PACKET_CMD_UNSPEC  = 0,
    OVS_PACKET_CMD_MISS    = 1,
    OVS_PACKET_CMD_ACTION  = 2,
    OVS_PACKET_CMD_EXECUTE = 3,
};

TRACEPOINT_PROBE(openvswitch, ovs_dp_upcall)
{
    struct event_t *event;
    struct packet_buffer *buff;
    struct sk_buff *skb;
    uint32_t update_id, pid = bpf_get_current_pid_tgid();
    int zero = 0;

    upcalls.delete(&pid);
    skb = args->skbaddr;
    if (skb == NULL || skb->data == NULL)
        return 0;

    event = init_event(EVENT_DP_UPCALL);
    if (!event) {
        return 1;
    }


    buff = packet_buffers.lookup(&zero);
    if (!buff)
        goto drop;

    TP_DATA_LOC_READ_CONST(&event->dpif_name, dp_name,
                           sizeof(event->dpif_name));
    TP_DATA_LOC_READ_CONST(&event->dev_name, dev_name,
                           sizeof(event->dev_name));

    update_id = hash_skb(buff, skb, event->ts & 0xfffffff);
    event->upcall_id = update_id;

    event->pkt_size = skb->len;
    if (skb->data_len != 0) {
        event->pkt_frag_size = (skb->len - skb->data_len) & 0xfffffff;
    } else {
        event->pkt_frag_size = 0;
    }

    upcalls.update(&pid, &update_id);
    events.ringbuf_submit(event, 0);
    return 0;

drop:
    bpf_ringbuf_discard(event, BPF_RB_NO_WAKEUP);
    dropcnt_inc(EVENT_DP_UPCALL);
    return 1;
}

int kprobe__queue_userspace_packet(struct pt_regs *ctx,
                  struct datapath *dp, struct sk_buff *skb,
                  const struct sw_flow_key *key,
                  const struct dp_upcall_info *upcall_info,
                  uint32_t cutlen)
{
    uint32_t pid;

    if (upcall_info->cmd != OVS_PACKET_CMD_MISS) {
        return 0;
    }

    pid = bpf_get_current_pid_tgid();
    queue_args.update(&pid, &skb);
    return 0;
}

int kretprobe__queue_userspace_packet(struct pt_regs *ctx)
{
    uint64_t data_size, size;
    uint32_t *upcall_id, zero = 0;
    struct event_t *event;
    struct packet_buffer *buff;
    struct sk_buff *skb, **skbp;
    uint32_t pid = bpf_get_current_pid_tgid();

    skbp = queue_args.lookup(&pid);
    if (!skbp) {
        dropcnt_inc(EVENT_DP_UPCALL_QUEUE);
        return 1;
    }
    skb = *skbp;

    if (skb == NULL || skb->data == NULL)
        return 0;

    upcall_id = upcalls.lookup(&pid);
    if (!upcall_id) {
        /* We've missed the previous EVENT_DP_UPCALL or it got dropped. */
        dropcnt_inc(EVENT_DP_UPCALL_QUEUE);
        return 1;
    }

    buff = packet_buffers.lookup(&zero);
    if (!buff) {
        dropcnt_inc(EVENT_DP_UPCALL_QUEUE);
        return 1;
    }

    event = init_event(EVENT_DP_UPCALL_QUEUE);
    if (!event) {
        return 1;
    }
    event->res = PT_REGS_RC(ctx);

    event->pkt_size = skb->len;
    if (skb->data_len != 0) {
        event->pkt_frag_size = (skb->len - skb->data_len) & 0xfffffff;
        size = event->pkt_frag_size;
    } else {
        event->pkt_frag_size = 0;
        size = event->pkt_size;
    }

    bpf_probe_read_kernel(&event->dev_name,
                          sizeof(event->dev_name),
                          skb->dev->name);

    event->queue_id = hash_skb(buff, skb, 0);
    event->upcall_id = *upcall_id;

    events.ringbuf_submit(event, 0);
    return 0;
}

TRACEPOINT_PROBE(openvswitch, ovs_do_execute_action)
{
    struct event_t *event;
    struct packet_buffer *buff;
    struct sk_buff *skb;
    uint32_t *inflight, queue_id, zero = 0;

    skb = args->skbaddr;
    if (skb == NULL || skb->data == NULL)
        return 0;

    buff = packet_buffers.lookup(&zero);
    if (!buff) {
        dropcnt_inc(EVENT_OVS_PKT_EXEC);
        return 1;
    }

    queue_id = hash_skb(buff, args->skbaddr, 0);

    /* This is vulnerable to race conditions. However, we don't have a good
     * way to address it at the moment. */
    inflight = in_flight_exec.lookup(&queue_id);
    if (!inflight) {
        /* This action does not come from an upcall. Ignore it. */
        return 0;
    }
    in_flight_exec.delete(&queue_id);

    event = init_event(EVENT_OVS_PKT_EXEC);
    if (!event) {
        return 1;
    }

    event->queue_id = queue_id;

    events.ringbuf_submit(event, 0);
    return 0;
}

/* Userspace side. */
struct user_upcall_info {
    uint32_t queue_id;

#define UPCALL_HAS_PUT 1 << 1
#define UPCALL_HAS_EXEC 1 << 2
    uint8_t flags;
};

struct upcall_batch {
    uint64_t leader_ts;     /* Timestamp of the first upcall in the batch. */
    bool processing;        /* Whether we're still batching (false) or we
                             are processing batched upcalls. */
    uint8_t current_upcall; /* Current upcall being processed */
    uint8_t total;          /* Number of upcalls of the batch */
    struct user_upcall_info upcalls[UPCALL_MAX_BATCH]; /* Upcalls in batch */
};

/* Upcall batches can get too big to be allocated in the stack.
 * An array is used to preallocate one for each handler.*/
BPF_ARRAY(upcall_batches, struct upcall_batch, MAX_HANDLERS);
BPF_HASH(pid_to_batch, int32_t, int32_t);

/* Get the batch for the current thread. */
static struct upcall_batch *batch_get() {
    uint32_t *idx;
    uint32_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    idx = pid_to_batch.lookup(&pid);
    if (!idx)
        return NULL;
    return upcall_batches.lookup(idx);
}

static void batch_new(struct upcall_batch *batch) {
    if (!batch)
        return;

    batch->processing = false;
    batch->leader_ts = 0;
    batch->current_upcall = 0;
    batch->total = 0;
}

static void batch_start_processing(struct upcall_batch *batch) {
    if (!batch)
        return;
    batch->current_upcall = 0;
    batch->processing = true;
}

static bool batch_is_processing(const struct upcall_batch *batch) {
    if (!batch)
        return false;
    return batch->processing;
}

static struct user_upcall_info *batch_current(struct upcall_batch *batch) {
    if (!batch ||
        batch->current_upcall >= (UPCALL_MAX_BATCH) )
        return NULL;

    return &batch->upcalls[batch->current_upcall];
}

static struct user_upcall_info *batch_next(struct upcall_batch *batch) {
    if (!batch ||
        batch->current_upcall >= (batch->total -1) ||
        batch->current_upcall >= (UPCALL_MAX_BATCH -1) )
        return NULL;

    batch->current_upcall += 1;

    return batch_current(batch);
}

static struct user_upcall_info *batch_put(struct upcall_batch *batch) {
    struct user_upcall_info *dst;
    struct user_upcall_info info = {0};
    info.queue_id = 0xFFFFFF;
    info.flags = 0;

    if (!batch) {
        return NULL;
    }
    if (batch->total >= UPCALL_MAX_BATCH -1) {
        return NULL;
    }

    dst = &batch->upcalls[batch->total];
    memcpy(dst, &info, sizeof(info));
    batch->total += 1;

    return dst;
}

int trace__recv_upcall(struct pt_regs *ctx) {
    uint64_t addr, size;
    uint32_t upcall_type, hash;
    int zero = 0;
    struct packet_buffer *buff;
    struct upcall_batch *batch;
    struct user_upcall_info *info;

    bpf_usdt_readarg(2, ctx, &upcall_type);
    if (upcall_type != 0)
        return 0;

    struct event_t *event = init_event(EVENT_RECV_UPCALL);
    if (!event)
        return 1;

    buff = packet_buffers.lookup(&zero);
    if (buff == 0)
        goto drop;

    /* Append upcall to batch. */
    batch = batch_get();
    if (!batch)
        goto drop;

    if (batch_is_processing(batch)) {
        batch_new(batch);
    }

    info = batch_put(batch);
    if (!info)
        goto drop;

    if (batch->total == 1) {
        /* First of the batch. */
        batch->leader_ts = event->ts;
    }

    /* Populate event information. */
    event->batch_ts = batch->leader_ts;

    bpf_usdt_readarg(1, ctx, &addr);
    bpf_probe_read_str(&event->dpif_name, sizeof(event->dpif_name),
                       (void *)addr);

    bpf_usdt_readarg(4, ctx, &event->pkt_size);
    bpf_usdt_readarg(6, ctx, &event->key_size);

    bpf_usdt_readarg(3, ctx, &addr);
    event->queue_id = hash_packet(buff, (void *) addr, event->pkt_size, 0);
    info->queue_id = event->queue_id;
    event->batch_idx = batch->current_upcall;

    if (event->pkt_size > MAX_PACKET)
        size = MAX_PACKET;
    else
        size = event->pkt_size;
    barrier_var(size);
    bpf_probe_read(&event->pkt, size, (void *)addr);

    bpf_usdt_readarg(5, ctx, &addr);
    if (event->key_size > MAX_KEY)
        size = MAX_KEY;
    else
        size = event->key_size;
    barrier_var(size);
    bpf_probe_read(&event->key, size, (void *)addr);

    events.ringbuf_submit(event, 0);
    return 0;

drop:
    bpf_ringbuf_discard(event, BPF_RB_NO_WAKEUP);
    dropcnt_inc(EVENT_RECV_UPCALL);
    return 1;
};

int trace__op_flow_put(struct pt_regs *ctx)
{
    struct upcall_batch *batch;
    struct user_upcall_info *info;

    struct event_t *event = init_event(EVENT_OP_FLOW_PUT);
    if (!event) {
        return 1;
    }

    batch = batch_get();
    if (!batch)
        goto drop;

    if (!batch_is_processing(batch)) {
        batch_start_processing(batch);
    }

    info = batch_current(batch);
    if (!info)
        goto drop;

    if (info->flags & UPCALL_HAS_PUT) {
        /* This event must correspond to the next upcall in the batch. */
        info = batch_next(batch);
        if (!info)
            goto drop;
    }
    info->flags |= UPCALL_HAS_PUT;

    event->queue_id = info->queue_id;
    event->batch_ts = batch->leader_ts;
    event->batch_idx = batch->current_upcall;

    events.ringbuf_submit(event, 0);
    return 0;

drop:
    bpf_ringbuf_discard(event, BPF_RB_NO_WAKEUP);
    dropcnt_inc(EVENT_OP_FLOW_PUT);
    return 1;
};


int trace__op_flow_execute(struct pt_regs *ctx)
{
    uint64_t addr, size;
    struct upcall_batch *batch;
    struct user_upcall_info *info;
    int zero = 0;

    struct event_t *event = init_event(EVENT_OP_FLOW_EXECUTE);
    if (!event) {
        return 1;
    }

    batch = batch_get();
    if (!batch)
        goto drop;

    if (!batch_is_processing(batch)) {
        batch_start_processing(batch);
    }

    info = batch_current(batch);
    if (!info)
        goto drop;

    if (info->flags & UPCALL_HAS_EXEC) {
        /* This event must correspond to the next upcall in the batch. */
        info = batch_next(batch);
        if (!info)
            goto drop;
    }
    info->flags |= UPCALL_HAS_EXEC;

    in_flight_exec.update(&info->queue_id, &zero);

    event->queue_id = info->queue_id;
    event->batch_ts = batch->leader_ts;
    event->batch_idx = batch->current_upcall;

    events.ringbuf_submit(event, 0);
    return 0;

drop:
    bpf_ringbuf_discard(event, BPF_RB_NO_WAKEUP);
    dropcnt_inc(EVENT_OP_FLOW_EXECUTE);
    return 1;
};

"""


#
# Event types
#
class EventType(StrEnum):
    RECV_UPCALL = "dpif_recv__recv_upcall"
    DP_UPCALL = "openvswitch__dp_upcall"
    DP_UPCALL_QUEUE = "kprobe__queue_userspace_packet"
    OP_FLOW_PUT = "dpif_netlink_operate__op_flow_put"
    OP_FLOW_EXECUTE = "dpif_netlink_operate__op_flow_execute"
    OVS_PKT_EXEC = "ktrace__ovs_packet_cmd_execute"
    ERR = "ERR"

    def from_trace(trace_event):
        if trace_event == 0:
            return EventType.RECV_UPCALL
        elif trace_event == 1:
            return EventType.DP_UPCALL
        elif trace_event == 2:
            return EventType.DP_UPCALL_QUEUE
        elif trace_event == 3:
            return EventType.OP_FLOW_PUT
        elif trace_event == 4:
            return EventType.OP_FLOW_EXECUTE
        elif trace_event == 5:
            return EventType.OVS_PKT_EXEC
        elif trace_event == 6:
            return EventType.ERR

        raise ValueError("Event type not supported {}".format(trace_event))


#
# Event Base Class
#
class Event(object):
    def __init__(
        self,
        ts,
        pid,
        comm,
        cpu,
        event_type,
        queue_id,
        dpif_name="",
        dp_port=None,
        pkt_len=None,
        pkt_frag_len=None,
    ):
        self.ts = ts
        self.pid = pid
        self.comm = comm
        self.cpu = cpu
        self.event_type = event_type
        self.queue_id = queue_id
        self.dpif_name = dpif_name
        self.dp_port = dp_port
        self.pkt_len = pkt_len
        self.pkt_frag_len = pkt_frag_len

    def __str__(self):
        return ("{:<24} {:<19} {:<16} {:8} [{:03}] {:18.9f}:"
            "{:<17} {:4} {:4} {:4}").format(
            "[{}]".format(Event.shorten(self.event_type, 24)),
            "({})".format(Event.shorten(self.format_id(), 17)),
            self.comm,
            self.pid,
            self.cpu,
            self.ts / 1000000000,
            Event.shorten(self.dpif_name or "", 17),
            self.dp_port or "",
            self.pkt_len or "",
            self.pkt_frag_len or "",
        )

    def format_id(self):
        return "{:0x}".format(self.queue_id)

    def __repr__(self):
        more = ""
        if self.__class__.__name__ != "Event":
            more = ", ..."

        return "{}({}, {}, {}, {}, {}{})".format(
            self.__class__.__name__,
            self.ts,
            self.pid,
            self.comm,
            self.cpu,
            self.event_type,
            more,
        )

    def handle_event(event):
        event = Event(
            event.ts,
            event.pid,
            event.comm.decode("utf-8"),
            event.cpu,
            EventType.from_trace(event.event),
            event.queue_id,
        )

        if not options.quiet:
            print(event)

        return event

    def get_event_header_str():
        return "{:<24}  {:<19} {:<16} {:>8}  {:<3}  {:<18}  {}".format(
            "EVENT",
            "(IDs)",
            "COMM",
            "PID",
            "CPU",
            "TIME",
            "EVENT DATA[dpif_name/dp_port/pkt_len/pkt_frag_len]",
        )

    def shorten(string, length):
        if not string:
            return ""

        if len(string) < length:
            return string

        return ".." + string[-(length - 2) :]


#
# dp_exec event class
#
DpExec = Event


class OvsOperation(Event):
    def __init__(
        self, ts, pid, comm, cpu, event_type, queue_id, batch_ts, batch_idx
    ):
        self.batch_ts = batch_ts
        self.batch_idx = batch_idx

        super(OvsOperation, self).__init__(
            ts, pid, comm, cpu, event_type, queue_id
        )

    def handle_event(event):
        event = OvsOperation(
            event.ts,
            event.pid,
            event.comm.decode("utf-8"),
            event.cpu,
            EventType.from_trace(event.event),
            event.queue_id,
            event.batch_ts,
            event.batch_idx,
        )

        if not options.quiet:
            print(event)

        return event


#
# op_flow_put event class
#
OpFlowPut = OvsOperation

#
# op_flow_execute event class
#
OpFlowExecute = OvsOperation


#
# dp_upcall event class
#
class DpUpcall(Event):
    def __init__(
        self,
        ts,
        pid,
        comm,
        cpu,
        dpif_name,
        port,
        pkt,
        pkt_len,
        pkt_frag_len,
        upcall_id,
        queue_id,
    ):

        self.upcall_id = upcall_id
        self.pkt = pkt
        self.queue_events = []
        dp_port = get_dp_mapping(dpif_name, port)
        if dp_port is None:
            #
            # As we only identify interfaces at startup, new interfaces could
            # have been added, causing the lookup to fail. Just something to
            # keep in mind when running this in a dynamic environment.
            #
            raise LookupError("Can't find datapath port mapping!")

        super(DpUpcall, self).__init__(
            ts,
            pid,
            comm,
            cpu,
            EventType.DP_UPCALL,
            queue_id,
            dpif_name,
            dp_port,
            pkt_len,
            pkt_frag_len,
        )

    def format_id(self):
        return "{:0x}/{:0x}".format(self.upcall_id, self.queue_id)

    def append_queue_event(self, event):
        self.queue_events.append(event)
        self.queue_events.sort(key=lambda x: x.ts)
        event.set_dpif_name(self.dpif_name)

    def handle_event(event):
        if event.pkt_size < options.packet_size:
            pkt_len = event.pkt_size
        else:
            pkt_len = options.packet_size

        pkt_data = bytes(event.pkt)[:pkt_len]

        try:
            event = DpUpcall(
                event.ts,
                event.pid,
                event.comm.decode("utf-8"),
                event.cpu,
                event.dpif_name.decode("utf-8"),
                event.dev_name.decode("utf-8"),
                pkt_data,
                event.pkt_size,
                event.pkt_frag_size,
                event.upcall_id,
                event.queue_id,
            )
        except LookupError:
            #
            # If we can't do the port lookup, ignore this event.
            #
            return None

        if not options.quiet:
            print(event)

        return event


#
# dp_upcall event class
#
class DpUpcallQueue(Event):
    def __init__(
        self,
        ts,
        pid,
        comm,
        cpu,
        port,
        pkt_len,
        pkt_frag_len,
        upcall_id,
        queue_id,
        res,
    ):

        self.res = res
        self.upcall_id = upcall_id
        self.nested = {}

        super(DpUpcallQueue, self).__init__(
            ts,
            pid,
            comm,
            cpu,
            EventType.DP_UPCALL_QUEUE,
            queue_id,
            "",
            port,
            pkt_len,
            pkt_frag_len,
        )

    def format_id(self):
        return "{:0x}/{:0x}".format(self.upcall_id, self.queue_id)

    def set_dpif_name(self, dpif_name):
        """Lazy port resolution."""
        self.dpif_name = dpif_name
        dp_port = get_dp_mapping(self.dpif_name, self.dp_port)
        if dp_port is None:
            #
            # As we only identify interfaces at startup, new interfaces could
            # have been added, causing the lookup to fail. Just something to
            # keep in mind when running this in a dynamic environment.
            #
            raise LookupError("Can't find datapath port mapping!")
        self.dp_port = dp_port

    def append_event(self, event):
        if self.nested.get(event.event_type):
            raise ValueError(
                "Event of type {} appended to Queue {} twice."
                "This {}. Orig: {}".format(
                    event.event_type,
                    self,
                    event,
                    self.nested.get(event.event_type),
                )
            )
        self.nested[event.event_type] = event

    def handle_event(event):
        event = DpUpcallQueue(
            event.ts,
            event.pid,
            event.comm.decode("utf-8"),
            event.cpu,
            event.dev_name.decode("utf-8"),
            event.pkt_size,
            event.pkt_frag_size,
            event.upcall_id,
            event.queue_id,
            event.res,
        )

        if not options.quiet:
            print(event)

        return event


#
# recv_upcall event class
#
class RecvUpcall(Event):
    def __init__(
        self,
        ts,
        pid,
        comm,
        cpu,
        key,
        pkt,
        pkt_len,
        upcall_id,
        queue_id,
        batch_ts,
        batch_idx,
    ):
        self.pkt = pkt
        self.key = key
        self.batch_ts = batch_ts
        self.batch_idx = batch_idx

        super(RecvUpcall, self).__init__(
            ts,
            pid,
            comm,
            cpu,
            EventType.RECV_UPCALL,
            queue_id,
            None,
            None,
            pkt_len,
        )

    def print_keys(self):
        return RecvUpcall.decode_nlm(self.key, indent=4, dump=True)

    def packet(self):
        return Ether(self.pkt)

    def decode_nlm(msg, indent=4, dump=True):
        bytes_left = len(msg)
        result = {}

        while bytes_left:
            if bytes_left < 4:
                if dump:
                    print(
                        "{}WARN: decode truncated; can't read header".format(
                            " " * indent
                        )
                    )
                break

            nla_len, nla_type = struct.unpack("=HH", msg[:4])

            if nla_len < 4:
                if dump:
                    print(
                        "{}WARN: decode truncated; nla_len < 4".format(
                            " " * indent
                        )
                    )
                break

            nla_data = msg[4:nla_len]
            trunc = ""

            if nla_len > bytes_left:
                trunc = "..."
                nla_data = nla_data[: (bytes_left - 4)]
                if (
                    RecvUpcall.get_ovs_key_attr_str(nla_type)
                    == "OVS_KEY_ATTR_TUNNEL"
                ):
                    #
                    # If we have truncated tunnel information, we still would
                    # like to know. This is due to the special tunnel handling
                    # needed for port matching.
                    #
                    result[RecvUpcall.get_ovs_key_attr_str(nla_type)] = bytes()
            else:
                result[RecvUpcall.get_ovs_key_attr_str(nla_type)] = nla_data

            if dump:
                print(
                    "{}nla_len {}, nla_type {}[{}], data: {}{}".format(
                        " " * indent,
                        nla_len,
                        RecvUpcall.get_ovs_key_attr_str(nla_type),
                        nla_type,
                        "".join("{:02x} ".format(b) for b in nla_data),
                        trunc,
                    )
                )

            if trunc != "":
                if dump:
                    print(
                        ("{}WARN: decode truncated; "
                        "nla_len > msg_len[{}]").format(
                            " " * indent, bytes_left
                        )
                    )
                break

            # Update next offset, but make sure it's aligned correctly.
            next_offset = (nla_len + 3) & ~(3)
            msg = msg[next_offset:]
            bytes_left -= next_offset

        return result

    def get_ovs_key_attr_str(attr):
        ovs_key_attr = [
            "OVS_KEY_ATTR_UNSPEC",
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
            "OVS_KEY_ATTR_NSH",
        ]

        if attr < 0 or attr > len(ovs_key_attr):
            return "<UNKNOWN>"

        return ovs_key_attr[attr]

    def handle_event(event):
        if event.key_size < options.flow_key_size:
            key_len = event.key_size
        else:
            key_len = options.flow_key_size

        if event.pkt_size < options.packet_size:
            pkt_len = event.pkt_size
        else:
            pkt_len = options.packet_size

        try:
            event = RecvUpcall(
                event.ts,
                event.pid,
                event.comm.decode("utf-8"),
                event.cpu,
                bytes(event.key)[:key_len],
                bytes(event.pkt)[:pkt_len],
                event.pkt_size,
                event.upcall_id,
                event.queue_id,
                event.batch_ts,
                event.batch_idx,
            )
        except LookupError:
            return None

        if not options.quiet:
            print(event)

        return event


#
# get_dp_mapping()
#
def get_dp_mapping(dp, port, return_map=False, dp_map=None):
    if dp_map is not None:
        get_dp_mapping.dp_port_map_cache = dp_map

    #
    # Build a cache, so we do not have to execue the ovs command each time.
    #
    if not hasattr(get_dp_mapping, "dp_port_map_cache"):
        try:
            output = subprocess.check_output(
                ["ovs-appctl", "dpctl/show"], encoding="utf8"
            ).split("\n")
        except subprocess.CalledProcessError:
            output = ""
            pass

        current_dp = None
        get_dp_mapping.dp_port_map_cache = {}

        for line in output:
            match = re.match("^system@(.*):$", line)
            if match is not None:
                current_dp = match.group(1)

            match = re.match("^  port ([0-9]+): ([^ /]*)", line)
            if match is not None and current_dp is not None:
                try:
                    get_dp_mapping.dp_port_map_cache[current_dp][
                        match.group(2)
                    ] = int(match.group(1))
                except KeyError:
                    get_dp_mapping.dp_port_map_cache[current_dp] = {
                        match.group(2): int(match.group(1))
                    }

    if return_map:
        return get_dp_mapping.dp_port_map_cache

    if (
        dp not in get_dp_mapping.dp_port_map_cache
        or port not in get_dp_mapping.dp_port_map_cache[dp]
    ):
        return None

    return get_dp_mapping.dp_port_map_cache[dp][port]


#
# event_to_dict()
#
def event_to_dict(event):
    event_dict = {}

    for field, _ in event._fields_:
        if isinstance(getattr(event, field), (int, bytes)):
            event_dict[field] = getattr(event, field)
        else:
            if (field == "key" and event.key_size == 0) or (
                field == "pkt" and event.pkt_size == 0
            ):
                data = bytes()
            else:
                data = bytes(getattr(event, field))

            event_dict[field] = data

    return event_dict


#
# receive_event_bcc()
#
def receive_event_bcc(ctx, data, size):
    event = b["events"].event(data)

    if export_file is not None:
        export_file.write("event = {}\n".format(event_to_dict(event)))

    receive_event(event)


#
# receive_event()
#
def receive_event(event):
    global event_tracer

    event_tracer.recv_event(event)


class EventTracer:
    """
    TraceData performs live sorting of trace events.
    """

    def __init__(self):
        self.events = []  # All the events.
        self.per_thread = {}  # Upcall recv events per thread
        self.per_batch = {}  # Upcall recv events per batch
        # Indexed by (cpu, batch_ts)
        self.upcalls = {}  # Upcall events indexed by upcall_id
        self.queue = {}  # Upcall queue events indexed by queue_id
        self.stats = {
            "total": {},
            "valid": {},
            "miss": {},
            "dup_upcalls": 0,
            "dup_queue": 0,
            "orfan": {},
        }
        self.received = 0
        self.num_upcalls = 0

    def list_upcalls(self):
        """Return all upcalls in a generator."""
        return chain.from_iterable(v for _, v in self.upcalls.items())

    def handle_upcall(self, event):
        entry = self.upcalls.get(event.upcall_id)
        if entry:
            self.stats["dup_upcalls"] += 1
            entry.append(event)
        else:
            self.upcalls[event.upcall_id] = [event]
            self.num_upcalls += 1

    def handle_upcall_enqueue(self, event):
        entry = self.queue.get(event.queue_id)
        if entry:
            self.stats["dup_queue"] += 1
            entry.append(event)
        else:
            self.queue[event.queue_id] = [event]

        #
        # Find the parent upcall (i.e: dp_upcall event) and append to it.
        #
        upcalls = self.upcalls.get(event.upcall_id)
        if not upcalls:
            try:
                self.stats["orfan"][event.event_type] += 1
            except KeyError:
                self.stats["orfan"][event.event_type] = 1
        else:
            # Just in case there are more than one possible parent upcall with
            # the same upcall_id (which is rare), append to the latest one.
            upcalls[-1].append_queue_event(event)

    def handle_recv(self, event):
        #
        # Batch counting.
        #
        if event.batch_ts != 0:
            idx = (event.comm, event.batch_ts)
            if idx not in self.per_batch:
                self.per_batch[idx] = 0
            self.per_batch[idx] += 1

        #
        # Thread counting.
        #
        if event.comm not in self.per_thread:
            self.per_thread[event.comm] = 0
        self.per_thread[event.comm] += 1

        #
        # Find the correspondent upcall enqueue event.
        #
        def find_queue(q):
            return q.nested.get(EventType.RECV_UPCALL) is None

        self.find_queue_and_append(event, find_queue)

    def handle_op(self, event):
        def find_queue(q):
            return (
                q.nested.get(event.event_type) is None
                and q.nested.get(EventType.RECV_UPCALL) is not None
                and q.nested.get(EventType.RECV_UPCALL).batch_ts
                == event.batch_ts
                and q.nested.get(EventType.RECV_UPCALL).batch_idx
                == event.batch_idx
            )

        self.find_queue_and_append(event, find_queue)

    def handle_exec(self, event):
        def find_queue(q):
            return (
                q.nested.get(event.event_type) is None
                and q.nested.get(EventType.RECV_UPCALL) is not None
                and q.nested.get(EventType.OP_FLOW_EXECUTE) is not None
            )

        self.find_queue_and_append(event, find_queue)

    def find_queue_and_append(self, nested, filter_fn):
        queues = self.queue.get(nested.queue_id)
        if not queues or len(queues) == 0:
            try:
                self.stats["orfan"][nested.event_type] += 1
            except KeyError:
                self.stats["orfan"][nested.event_type] = 1
        else:
            queue = next(filter(filter_fn, queues), None)
            if not queue:
                try:
                    self.stats["orfan"][nested.event_type] += 1
                except KeyError:
                    self.stats["orfan"][nested.event_type] = 1
            else:
                queue.append_event(nested)

    def recv_event(self, raw):
        self.received += 1
        if raw.event == 0:
            event = RecvUpcall.handle_event(raw)
        elif raw.event == 1:
            event = DpUpcall.handle_event(raw)
        elif raw.event == 2:
            event = DpUpcallQueue.handle_event(raw)
        elif raw.event == 3:
            event = OpFlowPut.handle_event(raw)
        elif raw.event == 4:
            event = OpFlowExecute.handle_event(raw)
        elif raw.event == 5:
            event = DpExec.handle_event(raw)

        try:
            self.stats["total"][EventType.from_trace(raw.event)] += 1
        except KeyError:
            self.stats["total"][EventType.from_trace(raw.event)] = 1
            self.stats["valid"][EventType.from_trace(raw.event)] = 0

        if event is not None:
            self.stats["valid"][event.event_type] += 1
            self.events.append(event)

    def handle_event(self, event):
        if event.event_type == EventType.RECV_UPCALL:
            self.handle_recv(event)
        elif event.event_type == EventType.DP_UPCALL:
            self.handle_upcall(event)
        elif event.event_type == EventType.DP_UPCALL_QUEUE:
            self.handle_upcall_enqueue(event)
        elif event.event_type == EventType.OP_FLOW_PUT:
            self.handle_op(event)
        elif event.event_type == EventType.OP_FLOW_EXECUTE:
            self.handle_op(event)
        elif event.event_type == EventType.OVS_PKT_EXEC:
            self.handle_exec(event)
        else:
            raise ValueError("Event type not supported {}".format(event))

    def analyze(self, profile=False):
        print("- Analyzing results ({} events)...".format(len(self.events)))
        t1_time = 0

        def t1_start():
            nonlocal t1_time
            t1_time = process_time()

        def t1_stop(description):
            print(
                "* PROFILING: {:<50}: {:.06f} seconds".format(
                    description, process_time() - t1_time
                )
            )

        if profile:
            t1_start()

        with alive_bar(
            len(self.events),
            title="- Matching DP_UPCALLs to RECV_UPCALLs",
            spinner=None,
            disable=False,
        ) as bar:
            for event in self.events:
                self.handle_event(event)
                bar()

        if profile:
            t1_stop("Handling events")

        if self.received > 0:
            if sum(self.stats["miss"].values()) > 0:
                print(
                    "\nWARNING: Not all events were captured!\n         "
                    "Increase the BPF ring buffer size with the "
                    "--buffer-page-count option."
                )

            print("\n=> Event statistics:")
            print(
                "  {:<50} {:10} {:10} {:10} {:10}".format(
                    "EVENT", "TOTAL", "VALID", "MISS", "ORFAN"
                )
            )
            for event, total in sorted(self.stats["total"].items()):
                miss = self.stats["miss"].get(event) or 0
                orfan = self.stats["orfan"].get(event) or 0
                print(
                    "  {:<45} {:10} {:10} {:10} {:10}".format(
                        event, total, self.stats["valid"][event], miss, orfan
                    )
                )

            if self.stats["dup_upcalls"] > 0 or self.stats["dup_queue"] > 0:
                print(
                    "\nWARNING: Some upcall events had the same identifiers!\n"
                    "Results might be inaccurate.\n"
                )
                print(
                    "=> Upcall duplicates: {}\n"
                    "   Upcall queue duplicates: {}".format(
                        self.stats["dup_upcalls"], self.stats["dup_queue"]
                    )
                )

        if len(self.upcalls.values()) <= 0:
            print("No upcall data sets where found!!")
            sys.exit(0)

        print("\n- Found {} event sets...".format(len(self.upcalls)))

        if options.show_groups or options.show_detail:
            detail = options.show_detail
            for upcall in self.list_upcalls():
                print("DBG: Upcall {}".format(upcall if detail else ""))
                for queue in upcall.queue_events:
                    print(
                        "DBG:   * {}{}{}{}{}".format(
                            "U",
                            "u"
                            if EventType.RECV_UPCALL in queue.nested
                            else "-",
                            "p"
                            if EventType.OP_FLOW_PUT in queue.nested
                            else "-",
                            "e"
                            if EventType.OP_FLOW_EXECUTE in queue.nested
                            else "-",
                            "E"
                            if EventType.OVS_PKT_EXEC in queue.nested
                            else "-",
                        )
                    )
                    if detail:
                        try:
                            print("DBG:   - {}".format(queue))
                            if EventType.RECV_UPCALL in queue.nested:
                                recv = queue.nested[EventType.RECV_UPCALL]
                                print("DBG:     - {}".format(recv))
                                if options.show_packets:
                                    packet = recv.packet()
                                    if packet:
                                        print(
                                            re.sub(
                                                "^",
                                                " " * 4,
                                                packet.show(dump=True),
                                                flags=re.MULTILINE,
                                            )
                                        )

                                if options.show_attributes:
                                    recv.print_keys()

                            if EventType.OP_FLOW_PUT in queue.nested:
                                print(
                                    "DBG:     - {}".format(
                                        queue.nested[EventType.OP_FLOW_PUT]
                                    )
                                )
                            if EventType.OP_FLOW_EXECUTE in queue.nested:
                                print(
                                    "DBG:     - {}".format(
                                        queue.nested[EventType.OP_FLOW_EXECUTE]
                                    )
                                )
                            if EventType.OVS_PKT_EXEC in queue.nested:
                                print(
                                    "DBG:     - {}".format(
                                        queue.nested[EventType.OVS_PKT_EXEC]
                                    )
                                )
                        except LookupError:
                            continue

        show_key_value(
            self.per_thread, description="Upcalls handled per thread"
        )
        show_batch_histogram(
            self.per_batch.values(),
            description="Histogram of upcalls per batch",
        )

        kernel_to_vswitchd = []
        kernel_to_kernel_exec = []
        vswitchd_to_kernel = []
        time_minus_lookup = []

        if profile:
            t1_start()

        with alive_bar(
            self.num_upcalls,
            title="- Calculating upcall cost",
            spinner=None,
            disable=False,
        ) as bar:
            for upcall in self.list_upcalls():
                for queue in upcall.queue_events:
                    nested = queue.nested
                    if EventType.RECV_UPCALL not in nested:
                        continue

                    kernel_to_vswitchd.append(
                        ((nested.get(EventType.RECV_UPCALL).ts - upcall.ts) /
                         1000)
                    )

                    if (
                        EventType.OP_FLOW_PUT in nested
                        and EventType.OVS_PKT_EXEC in nested
                    ):
                        time_minus_lookup.append(
                            (
                                (nested[EventType.OVS_PKT_EXEC].ts - queue.ts)
                                - (
                                    nested[EventType.OP_FLOW_PUT].ts
                                    - nested[EventType.RECV_UPCALL].ts
                                )
                            )
                            / 1000
                        )

                    if (
                        EventType.OP_FLOW_EXECUTE in nested
                        and EventType.OVS_PKT_EXEC in nested
                    ):
                        vswitchd_to_kernel.append(
                            (
                                nested[EventType.OVS_PKT_EXEC].ts
                                - nested[EventType.OP_FLOW_EXECUTE].ts
                            )
                            / 1000
                        )

                    if EventType.OVS_PKT_EXEC in nested:
                        kernel_to_kernel_exec.append(
                            ((nested[EventType.OVS_PKT_EXEC].ts - upcall.ts) /
                             1000)
                        )
                bar()

        show_histogram(
            kernel_to_vswitchd,
            description="Kernel upcall action to vswitchd receive "
            "(microseconds)",
            options=options,
        )
        show_histogram(
            vswitchd_to_kernel,
            description="vswitchd execute to kernel receive " "(microseconds)",
            options=options,
        )
        show_histogram(
            time_minus_lookup,
            description="Upcall overhead (total time minus lookup) "
            "(microseconds)",
            options=options,
        )
        show_histogram(
            kernel_to_kernel_exec,
            description="Kernel upcall to kernel packet execute "
            "(microseconds)",
            options=options,
        )

        if profile:
            t1_stop("Calculating upcall cost")


#
# show_key_value()
#
def show_key_value(data_set, description=None):
    if description is not None:
        print("\n=> {}:".format(description))

    for k, v in data_set.items():
        print("  {:36}: {:>10}".format(str(k), str(v)))


#
# show_batch_histogram()
#
def show_batch_histogram(data_set, description=None):
    nr_of_buckets = 64

    if description is not None:
        print("\n=> {}:".format(description))

    if len(data_set) == 0:
        print("# NumSamples = 0")
        return

    min_val = nr_of_buckets
    max_val = 0
    entries = 0
    high_buckets = 0
    buckets = [0] * nr_of_buckets

    for entry in data_set:
        min_val = min(min_val, entry)
        max_val = max(max_val, entry)
        if entry == 0:
            continue
        elif entry > nr_of_buckets:
            high_buckets += 1
        else:
            buckets[entry - 1] += 1

        entries += 1

    if max(buckets + [high_buckets]) > 4:
        scale = int(max(buckets + [high_buckets]) / 4)
    else:
        scale = 1

    print(
        "# NumSamples = {}; Min = {}; Max = {}".format(
            entries, min_val, max_val
        )
    )
    print("# each ∎ represents a count of {}".format(scale))

    for idx in range(int(nr_of_buckets / 2)):
        idx_2nd = idx + int(nr_of_buckets / 2)
        print(
            "{:5} [{:8}]: {:22}  {:5} [{:8}]: {:22}".format(
                idx + 1,
                buckets[idx],
                "∎" * int(buckets[idx] / scale),
                idx_2nd + 1,
                buckets[idx_2nd],
                "∎" * int(buckets[idx_2nd] / scale),
            )
        )

    if high_buckets > 0:
        print(
            "{:>5} [{:8}]: {:22}".format(
                ">" + str(nr_of_buckets),
                high_buckets,
                "∎" * int(high_buckets / scale),
            )
        )


#
# show_histogram()
#
def show_histogram(
    data_set,
    description=None,
    options=None,
    minimum=None,
    maximum=None,
    buckets=None,
    custbuckets=None,
):
    if description is not None:
        print("\n=> {}:".format(description))

    if options is not None:
        if buckets is None:
            buckets = options.histogram_buckets
        if options is not None and options.sets:
            print(data_set)

    if len(data_set) == 0:
        print("# NumSamples = 0")
    elif len(data_set) == 1:
        print(
            "# NumSamples = 1; Min = {0:.4f}; Max = {0:.4f}".format(
                data_set[0]
            )
        )
    elif (
        len(set(data_set)) == 1
        and maximum is None
        and minimum is None
        and custbuckets is None
    ):
        histogram(
            data_set,
            buckets=buckets,
            minimum=list(set(data_set))[0],
            maximum=list(set(data_set))[0] + 1,
        )
    else:
        histogram(
            data_set,
            buckets=buckets,
            minimum=minimum,
            maximum=maximum,
            custbuckets=custbuckets,
        )


#
# buffer_size_type()
#
def buffer_size_type(astr, min=64, max=2048):
    value = int(astr)
    if min <= value <= max:
        return value
    else:
        raise argparse.ArgumentTypeError(
            "value not in range {}-{}".format(min, max)
        )


#
# next_power_of_two()
#
def next_power_of_two(val):
    np = 1
    while np < val:
        np *= 2
    return np


#
# main()
#
def main():
    #
    # Don't like these globals, but ctx passing does not seem to work with the
    # existing open_ring_buffer() API :(
    #
    global b
    global options
    global event_tracer
    global export_file

    #
    # Argument parsing
    #
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-b",
        "--histogram-buckets",
        help="Number of buckets per histogram, default 20",
        type=int,
        default=20,
        metavar="BUCKETS",
    )
    parser.add_argument(
        "--buffer-page-count",
        help="Number of BPF ring buffer pages, default 1024",
        type=int,
        default=1024,
        metavar="NUMBER",
    )
    parser.add_argument(
        "-D",
        "--debug",
        help="Enable eBPF debugging",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-g",
        "--show-groups",
        help="Show processed upcall event groups in a summarized format",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-d",
        "--show-detail",
        help="Show processed upcall event groups in a detailed format",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-k",
        "--show-packets",
        help="Dump packet content of recv_upcall events"
        "A non-zero value must set using --packet-size. Implies '-d'",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-a",
        "--show-attributes",
        help="Dump netlink attributes of recv_upcall events"
        "A non-zero value must set using --flow-key-size. Implies '-d'",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-f",
        "--flow-key-size",
        help="Set maximum flow key size to capture, " "default 0",
        type=buffer_size_type,
        default=0,
        metavar="[0-2048]",
    )
    parser.add_argument(
        "--handler-filter",
        help="Post processing handler thread filter",
        type=str,
        default=None,
        metavar="HANDLERS",
    )
    parser.add_argument(
        "-P",
        "--packet-size",
        help="Set maximum packet size to capture, " "default 0",
        type=buffer_size_type,
        default=0,
        metavar="[0-2048]",
    )
    parser.add_argument(
        "-p",
        "--pid",
        metavar="VSWITCHD_PID",
        help="ovs-vswitch's PID",
        type=int,
        default=None,
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Do not show individual events",
    )
    parser.add_argument(
        "-r",
        "--read-events",
        help="Read events from FILE instead of installing " "tracepoints",
        type=str,
        default=None,
        metavar="FILE",
    )
    parser.add_argument(
        "--sets", action="store_true", help="Dump content of data sets"
    )
    parser.add_argument(
        "-s",
        "--stop",
        help="Stop after receiving EVENTS number of trace " "events",
        type=int,
        default=0,
        metavar="EVENTS",
    )
    parser.add_argument(
        "-w",
        "--write-events",
        help="Write events to FILE",
        type=str,
        default=None,
        metavar="FILE",
    )

    options = parser.parse_args()

    #
    # Find the PID of the ovs-vswitchd daemon if not specified.
    #
    if options.pid is None and options.read_events is None:
        for proc in psutil.process_iter():
            if "ovs-vswitchd" in proc.name():
                if options.pid is not None:
                    print(
                        "ERROR: Multiple ovs-vswitchd daemons running, "
                        "use the -p option!"
                    )
                    sys.exit(-1)

                options.pid = proc.pid

    #
    # Error checking on input parameters.
    #
    if options.pid is None and options.read_events is None:
        print("ERROR: Failed to find ovs-vswitchd's PID!")
        sys.exit(-1)

    if options.read_events is not None and options.write_events is not None:
        print(
            "ERROR: Either supply the read or write events option, "
            "not both!"
        )
        sys.exit(-1)

    if options.handler_filter is not None and options.read_events is None:
        print(
            "ERROR: The --handler-filter option is only valid with the "
            "--read-events option!"
        )
        sys.exit(-1)

    if not options.read_events and (
        options.show_packets and options.packet_size == 0
    ):
        print(
            "ERROR: The --show-packets option requires a non-zero value on "
            "the --packet-size packet option!"
        )
        sys.exit(-1)

    if not options.read_events and (
        options.show_attributes and options.flow_key_size == 0
    ):
        print(
            "ERROR: The --show-attributes option requires a non-zero value "
            "on the --flow-key-size option!"
        )
        sys.exit(-1)

    if options.show_packets or options.show_attributes:
        options.show_detail = True

    options.buffer_page_count = next_power_of_two(options.buffer_page_count)

    #
    # Open write handle if needed.
    #
    if options.write_events is not None:
        try:
            export_file = open(options.write_events, "w")
        except (FileNotFoundError, IOError, PermissionError) as e:
            print(
                'ERROR: Can\'t create export file "{}": {}'.format(
                    options.write_events, e.strerror
                )
            )
            sys.exit(-1)
    else:
        export_file = None

    event_tracer = EventTracer()

    if options.read_events is None:
        #
        # Call get_dp_mapping() to prepare the cache
        #
        dp_port_map = get_dp_mapping("ovs-system", "eth0", return_map=True)
        if export_file is not None:
            export_file.write("dp_port_map = {}\n".format(dp_port_map))

        #
        # Get pids of handler threads.
        #
        handlers = []
        ovs_proc = join("/", "proc", str(options.pid), "task")
        for pid in listdir(ovs_proc):
            path = join(ovs_proc, pid)
            if not isdir(path):
                continue
            with open(join(path, "comm")) as f:
                if "handler" in f.read():
                    handlers.append(pid)

        #
        # Attach the usdt probe
        #
        u = USDT(pid=int(options.pid))
        try:
            u.enable_probe(probe="recv_upcall", fn_name="trace__recv_upcall")
            u.enable_probe(probe="op_flow_put", fn_name="trace__op_flow_put")
            u.enable_probe(
                probe="op_flow_execute", fn_name="trace__op_flow_execute"
            )
        except USDTException as e:
            print(
                "ERROR: {}"
                "ovs-vswitchd!".format(
                    (re.sub("^", " " * 7, str(e), flags=re.MULTILINE))
                    .strip()
                    .replace(
                        "--with-dtrace or --enable-dtrace",
                        "--enable-usdt-probes",
                    )
                )
            )
            sys.exit(-1)

        #
        # Uncomment to see how arguments are decoded.
        #   print(u.get_text())
        #
        print("- Compiling eBPF programs...")

        #
        # Attach probes to the running process
        #
        source = ebpf_source.replace(
            "<MAX_PACKET_VAL>", str(options.packet_size)
        )
        source = source.replace("<MAX_KEY_VAL>", str(options.flow_key_size))
        source = source.replace(
            "<BUFFER_PAGE_CNT>", str(options.buffer_page_count)
        )
        source = source.replace("<PACKET_HASH_SIZE>", "64")
        source = source.replace("<UPCALL_MAX_BATCH>", "64")
        source = source.replace("<MAX_HANDLERS>", str(len(handlers)))

        b = BPF(text=source, usdt_contexts=[u], debug=options.debug)

        #
        # Pre-populate pid_to_batch map
        #
        for batch_id, pid in enumerate(handlers):
            b["pid_to_batch"][c_uint32(int(pid))] = c_uint32(batch_id)

        #
        # Dump out all events
        #
        print("- Capturing events [Press ^C to stop]...")

        if not options.quiet:
            print("\n" + Event.get_event_header_str())

        b["events"].open_ring_buffer(receive_event_bcc)
        while 1:
            try:
                b.ring_buffer_poll(5)
                if options.stop != 0 and event_tracer.received >= options.stop:
                    break
                time.sleep(0.5)
            except KeyboardInterrupt:
                break

        dropcnt = b.get_table("dropcnt")
        export_misses = {}
        for k in dropcnt.keys():
            event = EventType.from_trace(k.value)
            count = dropcnt.sum(k).value
            if count > 0:
                if event not in event_tracer.stats["total"]:
                    event_tracer.stats["total"][event] = 0
                    event_tracer.stats["valid"][event] = 0
                event_tracer.stats["miss"][event] = count
                export_misses[k.value] = count

        if options.write_events is not None:
            if sum(event_tracer.stats["miss"].values()) > 0:
                export_file.write("event_miss = {}\n".format(export_misses))

            export_file.close()

        print()
    else:
        #
        # Here we are requested to read event from an event export
        #
        thread_filter = None
        if options.handler_filter is not None:
            thread_filter = options.handler_filter.split(",")

        try:
            event_tracer = EventTracer()
            dp_port_mapping_valid = False
            with open(options.read_events, "r") as fd:
                events_received = 0

                if options.quiet:
                    spinner = Halo(
                        spinner="dots",
                        color="cyan",
                        text='Reading events from "{}"...'.format(
                            options.read_events
                        ),
                    )
                    spinner.start()
                else:
                    print(
                        '- Reading events from "{}"...'.format(
                            options.read_events
                        )
                    )

                if not options.quiet:
                    print("\n" + Event.get_event_header_str())

                for entry in fd:
                    if options.stop != 0 and events_received >= options.stop:
                        break

                    entry.rstrip()
                    if entry.startswith("dp_port_map = {"):
                        if not dp_port_mapping_valid:
                            dp_port_mapping_valid = True
                            get_dp_mapping(
                                "", "", dp_map=ast.literal_eval(entry[14:])
                            )
                    elif (
                        entry.startswith("event = {") and dp_port_mapping_valid
                    ):
                        event = ast.literal_eval(entry[8:])
                        event = namedtuple("EventObject", event.keys())(
                            *event.values()
                        )

                        if (
                            thread_filter is not None
                            and EventType.from_trace(event.event)
                            not in [
                                EventType.DP_UPCALL,
                                EventType.DP_UPCALL_QUEUE,
                            ]
                            and event.comm.decode("utf-8") not in thread_filter
                        ):
                            # Skip none filtered threads
                            continue

                        if len(event.pkt) > 0:
                            options.packet_size = len(event.pkt)
                        if len(event.key) > 0:
                            options.flow_key_size = len(event.key)
                        event_tracer.recv_event(event)

                    elif entry.startswith("event_miss = {"):
                        misses = ast.literal_eval(entry[13:])
                        for e, count in misses.items():
                            event = EventType.from_trace(e)
                            if count > 0:
                                if event not in event_tracer.stats["total"]:
                                    event_tracer.stats["total"][event] = 0
                                    event_tracer.stats["valid"][event] = 0
                                event_tracer.stats["miss"][event] = count

            if options.quiet:
                spinner.stop()
                print(
                    '- Reading events from "{}"...'.format(options.read_events)
                )

        except (FileNotFoundError, PermissionError):
            print(
                'ERROR: Can\'t open file "{}" for reading!'.format(
                    options.read_events
                )
            )
            sys.exit(-1)

    #
    # Start analyzing the data
    #
    event_tracer.analyze()


#
# Start main() as the default entry point...
#
if __name__ == "__main__":
    main()
