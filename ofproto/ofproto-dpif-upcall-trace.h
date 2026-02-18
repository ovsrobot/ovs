#ifndef OFPROTO_DPIF_UPCALL_TRACE_H
#define OFPROTO_DPIF_UPCALL_TRACE_H 1

#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-port.h"
#include "ovs-thread.h"

struct flow;
struct ofproto_dpif;
struct xlate_in;
struct xlate_out;

#define UPCALL_TRACE_DEFAULT_MAX_SIZE 64

/* upcall_tracing - The main upcall_tracing object configured by the user
 * and that stores all the generated traces. */
struct upcall_tracing {
    /* Match filter (optional). */
    struct match filter;

    struct ovs_mutex mutex;
    struct ovs_list blocks;     /* List of upcall_trace_block, oldest first. */
    size_t n_blocks;
    size_t max_blocks;
    uint64_t last_trace_id;
};
struct upcall_trace;

char * upcall_tracing_create(int argc, const char *argv[],
                             struct ofproto_dpif **ofprotop,
                             struct upcall_tracing **tracingp);
void upcall_tracing_destroy(struct upcall_tracing *);
void upcall_tracing_format(const struct upcall_tracing *, struct ds *);
void upcall_tracing_format_list(struct upcall_tracing *, struct ds *);
void upcall_tracing_format_id(struct upcall_tracing *, uint64_t trace_id,
                              struct ds *);

void upcall_tracing_flush(struct upcall_tracing *, uint64_t trace_id);
void upcall_tracing_flush_all(struct upcall_tracing *);

struct upcall_trace *
upcall_tracing_trace_from_flow(struct upcall_tracing *tracing,
                               const struct flow *flow,
                               const ofp_port_t *ofp_in_port);
struct upcall_trace *
upcall_tracing_append_to_id(struct upcall_tracing *tracing,
                            uint64_t trace_id,
                            uint32_t recirc_id,
                            const struct flow *flow);
struct ovs_list *upcall_trace_xlate_start(struct upcall_trace *,
                                         struct xlate_in *);
uint64_t upcall_trace_get_trace_id(const struct upcall_trace *);
void upcall_trace_unref(struct upcall_trace *);

#endif /*OFPROTO_DPIF_UPCALL_TRACE_H */
