#include <config.h>

#include "ofproto-dpif-upcall-trace.h"

#include "ofproto/ofproto-dpif-xlate.h"
#include "ofproto/ofproto-dpif-trace.h"
#include <openvswitch/dynamic-string.h>
#include <openvswitch/ofp-flow.h>
#include <openvswitch/ofp-port.h>
#include <openvswitch/vlog.h>
#include "ofproto-dpif.h"


VLOG_DEFINE_THIS_MODULE(upcall_trace);

struct upcall_trace_block;
struct upcall_trace;

static bool upcall_tracing_matches(const struct upcall_tracing *,
                                   const struct flow *,
                                   const ofp_port_t *);

/* upcall_trace - A single xlate result (one recirculation pass).
 *
 * An upcall_trace can be listed inside an "upcall_trace_block" and/or
 * referenced by an in-flight upcall. "refcount" is used to track these two
 * references.
 *
 * "list_node" should only be accessed through the associated
 * "upcall_trace_block" as it will get invalidated if removed from the block
 * list. "upcall"s can take pointer to the internal "xtrace_node" and add nodes
 * to the list.
 */
struct upcall_trace {
    struct ovs_list list_node;      /* In upcall_upcall_trace_block->traces. */
    struct ovs_refcount refcount;

    long long int timestamp_msec;
    uint32_t recirc_id;
    uint64_t trace_id;
    struct flow initial_flow;       /* Flow at start of this xlate. */

    /* The oftrace_node tree - moved from upcall_trace. */
    struct ovs_list xtrace_nodes;   /* List of struct xtrace_node. */
};

static struct upcall_trace *
upcall_trace_create(uint32_t recirc_id,
                    uint64_t trace_id,
                   const struct flow *flow)
{
    struct upcall_trace *trace = xzalloc(sizeof *trace);
    trace->recirc_id = recirc_id;
    trace->trace_id = trace_id;
    trace->timestamp_msec = time_wall_msec();
    trace->initial_flow = *flow;
    ovs_list_init(&trace->xtrace_nodes);
    ovs_refcount_init(&trace->refcount);
    return trace;
}

static void
upcall_trace_destroy(struct upcall_trace *trace)
{
    if (trace) {
        oftrace_node_list_destroy(&trace->xtrace_nodes);
        free(trace);
    }
}

static struct upcall_trace *
upcall_trace_ref(const struct upcall_trace *trace_)
{
    struct upcall_trace *trace = CONST_CAST(struct upcall_trace *, trace_);
    if (trace) {
        ovs_refcount_ref(&trace->refcount);
    }
    return trace;
}

void
upcall_trace_unref(struct upcall_trace *trace)
{
    if (trace && ovs_refcount_unref(&trace->refcount) == 1) {
        upcall_trace_destroy(trace);
    }
}

uint64_t
upcall_trace_get_trace_id(const struct upcall_trace *utrace)
{
    return utrace ? utrace->trace_id : 0;
}

struct ovs_list *
upcall_trace_xlate_start(struct upcall_trace *utrace,
                         struct xlate_in *xin)
{
    if (OVS_UNLIKELY(utrace)) {
        /* Copy initial flow - it may change during xlate. */
        utrace->initial_flow = xin->flow;
        utrace->recirc_id = xin->flow.recirc_id;
        if (!ovs_list_is_empty(&utrace->xtrace_nodes)) {
            VLOG_ERR("Started new xlate tracing without consuming previous");
            oftrace_node_list_destroy(&utrace->xtrace_nodes);
            ovs_list_init(&utrace->xtrace_nodes);
        }
        return &utrace->xtrace_nodes;
    }
    return NULL;
}

/* upcall_trace_block - A group of upcall_traces with the same trace_id. */
struct upcall_trace_block {
    struct ovs_list list_node;      /* In upcall_tracing->blocks. */
    uint64_t trace_id;
    struct ovs_list traces;          /* List of struct upcall_trace. */
};

static struct upcall_trace_block *
upcall_trace_block_create(uint64_t trace_id)
{
    struct upcall_trace_block *block = xzalloc(sizeof *block);
    block->trace_id = trace_id;
    ovs_list_init(&block->traces);
    return block;
}

static void
upcall_trace_block_destroy(struct upcall_trace_block *block)
{
    if (block) {
        struct upcall_trace *trace;
        LIST_FOR_EACH_POP (trace, list_node, &block->traces) {
            upcall_trace_unref(trace);
        }
        free(block);
    }
}

static void
upcall_trace_block_format_short(const struct upcall_trace_block *block,
                                struct ds *output)
{
    struct upcall_trace *trace;
    ds_put_format(output, "trace_id=0x%"PRIx64, block->trace_id);
    if (!ovs_list_is_empty(&block->traces)) {
        trace = CONTAINER_OF(ovs_list_front(&block->traces),
                             struct upcall_trace, list_node);

        ds_put_strftime_msec(output, " ts=%H:%M:%S.###",
                             trace->timestamp_msec, false);

        ds_put_format(output, " nodes=%"PRIuSIZE" flow=",
                      ovs_list_size(&block->traces));
        flow_format(output, &trace->initial_flow, NULL);
    }
}

static void
upcall_trace_block_format(const struct upcall_trace_block *block,
                          struct ds *output)
{
    struct upcall_trace *trace;
    ds_put_format(output, "=== Trace 0x%"PRIx64" ===\n", block->trace_id);
    LIST_FOR_EACH (trace, list_node, &block->traces) {
        ds_put_format(output, "--- recirc_id=0x%"PRIx32" [",
                      trace->recirc_id);
        ds_put_strftime_msec(output, "%H:%M:%S.###",
                             trace->timestamp_msec, false);
        ds_put_cstr(output, "] ---\n");
        ds_put_cstr(output, "\nInitial flow: ");
        flow_format(output, &trace->initial_flow, NULL);
        ds_put_cstr(output, "\n");

        /* Format the xtrace_traces. */
        oftrace_node_print_details(output, &trace->xtrace_nodes, 0);
        ds_put_char(output, '\n');
    }
}
char * OVS_WARN_UNUSED_RESULT
upcall_tracing_create(int argc, const char *argv[],
                      struct ofproto_dpif **ofprotop,
                      struct upcall_tracing **tracingp)
{
    struct ofputil_port_map port_map = OFPUTIL_PORT_MAP_INITIALIZER(&port_map);
    struct upcall_tracing *tracing = xzalloc(sizeof *tracing);
    struct ofproto_dpif *ofproto = NULL;
    struct flow_wildcards wc_filter;
    const struct ofport *ofport;
    struct flow flow_filter;
    char *error = NULL;

    ovs_mutex_init(&tracing->mutex);
    ovs_list_init(&tracing->blocks);
    tracing->n_blocks = 0;
    tracing->last_trace_id = 0;
    tracing->max_blocks =  UPCALL_TRACE_DEFAULT_MAX_SIZE;

    if (argc < 3) {
        error = xasprintf("Missing arguments");
        goto exit;
    }

    ofproto = ofproto_dpif_lookup_by_name(argv[1]);
    if (!ofproto) {
        error = xasprintf("%s: unknown bridge", argv[1]);
        goto exit;
    }

    HMAP_FOR_EACH (ofport, hmap_node, &(ofproto->up.ports)) {
        ofputil_port_map_put(&port_map, ofport->ofp_port,
                             netdev_get_name(ofport->netdev));
    }

    error = parse_ofp_exact_flow(&flow_filter, &wc_filter, NULL, argv[2],
                                 &port_map);
    if (error) {
        goto exit;
    }
    match_init(&tracing->filter, &flow_filter, &wc_filter);


exit:
    if (error) {
        upcall_tracing_destroy(tracing);
        *tracingp = NULL;
    } else {
        *ofprotop = ofproto;
        *tracingp = tracing;
    }
    ofputil_port_map_destroy(&port_map);
    return error;
}

void
upcall_tracing_destroy(struct upcall_tracing *tracing)
{
    if (tracing) {
        upcall_tracing_flush_all(tracing);
        ovs_mutex_destroy(&tracing->mutex);
        free(tracing);
    }
}

void
upcall_tracing_format(const struct upcall_tracing *tracing, struct ds *output)
{
    if (tracing) {
        ovs_mutex_lock(&tracing->mutex);
        ds_put_format(output, "enabled, max_traces=%"PRIuSIZE", "
                      "current=%"PRIuSIZE", filter: ",
                      tracing->max_blocks, tracing->n_blocks);
        match_format(&tracing->filter, NULL, output, 0);
        ovs_mutex_unlock(&tracing->mutex);
    } else {
        ds_put_cstr(output, "disabled");
    }
}

static bool
upcall_tracing_matches(const struct upcall_tracing *tracing,
                     const struct flow *flowp,
                     const ofp_port_t *ofp_in_port)
{
    bool matches = false;
    struct minimatch minimatch;
    struct flow flow;
    if (ofp_in_port) {
        flow = *flowp;
        flow.in_port.ofp_port = *ofp_in_port;
        flowp = &flow;
    }
    minimatch_init(&minimatch, &tracing->filter);
    if (minimatch_matches_flow(&minimatch, flowp)) {
        matches = true;
    }
    minimatch_destroy(&minimatch);
    return matches;
}

static struct upcall_trace_block *
upcall_tracing_find_block__(struct upcall_tracing *tracing,
                                 uint64_t trace_id)
OVS_REQUIRES(tracing->mutex)
{
    struct upcall_trace_block *block;
    LIST_FOR_EACH (block, list_node, &tracing->blocks) {
        if (block->trace_id == trace_id) {
            return block;
        }
    }
    return NULL;
}

static void
upcall_tracing_evict_if_needed(struct upcall_tracing *tracing)
OVS_REQUIRES(tracing->mutex)
{
    struct upcall_trace_block *block;
    while (tracing->n_blocks >= tracing->max_blocks
           && !ovs_list_is_empty(&tracing->blocks)) {
        block = CONTAINER_OF(ovs_list_pop_front(&tracing->blocks),
                             struct upcall_trace_block, list_node);
        upcall_trace_block_destroy(block);
        VLOG_DBG("Deleted oldest trace block");
        tracing->n_blocks--;
    }
}

static uint64_t
upcall_tracing_id_generate(struct upcall_tracing *tracing)
OVS_REQUIRES(tracing->mutex)
{
    uint64_t id;
    if (tracing->last_trace_id == UINT64_MAX) {
        tracing->last_trace_id = 0;
    }
    id = ++tracing->last_trace_id;
    return id;
}

/* Create a new trace allocating a new block and trace_id for it.*/
struct upcall_trace *
upcall_tracing_trace_from_flow(struct upcall_tracing *tracing,
                               const struct flow *flow,
                               const ofp_port_t *ofp_in_port)
{
    struct upcall_trace *trace = NULL;
    struct upcall_trace_block *block;
    uint64_t trace_id;

    ovs_mutex_lock(&tracing->mutex);

    if (!upcall_tracing_matches(tracing, flow, ofp_in_port)) {
        goto out;
    }

    trace_id = upcall_tracing_id_generate(tracing);
    trace = upcall_trace_create(0, trace_id, flow);

    upcall_tracing_evict_if_needed(tracing);
    block = upcall_trace_block_create(trace_id);
    ovs_list_push_back(&tracing->blocks, &block->list_node);
    ovs_list_push_back(&block->traces, &trace->list_node);
    tracing->n_blocks++;

out:
    ovs_mutex_unlock(&tracing->mutex);
    return upcall_trace_ref(trace);
}

/* Create a new trace if a block with 'trace_id' is already present.*/
struct upcall_trace *
upcall_tracing_append_to_id(struct upcall_tracing *tracing,
                            uint64_t trace_id,
                            uint32_t recirc_id,
                            const struct flow *flow)
{
    struct upcall_trace *trace = NULL;
    struct upcall_trace_block *block;

    ovs_mutex_lock(&tracing->mutex);
    block = upcall_tracing_find_block__(tracing, trace_id);
    if (!block) {
        goto out;
    }

    trace = upcall_trace_create(recirc_id, trace_id, flow);
    ovs_list_push_back(&block->traces, &trace->list_node);
out:
    ovs_mutex_unlock(&tracing->mutex);
    return upcall_trace_ref(trace);
}

void
upcall_tracing_format_list(struct upcall_tracing *tracing, struct ds *output)
{
    ovs_mutex_lock(&tracing->mutex);

    if (ovs_list_is_empty(&tracing->blocks)) {
        ds_put_cstr(output, "No traces captured.\n");
    } else {
        struct upcall_trace_block *block;
        LIST_FOR_EACH (block, list_node, &tracing->blocks) {
            upcall_trace_block_format_short(block, output);
            if (&block->list_node != ovs_list_back(&tracing->blocks)) {
                ds_put_char(output, '\n');
            }
        }
    }

    ovs_mutex_unlock(&tracing->mutex);
}

/* Thread-safe version that finds and formats a block by trace_id.
 * Returns true if block was found and formatted. */
void
upcall_tracing_format_id(struct upcall_tracing *tracing,
                         uint64_t trace_id, struct ds *output)
{
    struct upcall_trace_block *block;

    ovs_mutex_lock(&tracing->mutex);

    block = upcall_tracing_find_block__(tracing, trace_id);
    if (block) {
        upcall_trace_block_format(block, output);
    }

    ovs_mutex_unlock(&tracing->mutex);
}

void
upcall_tracing_flush(struct upcall_tracing *tracing, uint64_t trace_id)
{
    struct upcall_trace_block *block;

    ovs_mutex_lock(&tracing->mutex);
    block = upcall_tracing_find_block__(tracing, trace_id);
    if (block) {
        ovs_list_remove(&block->list_node);
        upcall_trace_block_destroy(block);
        tracing->n_blocks--;
    }

    ovs_mutex_unlock(&tracing->mutex);
}

void
upcall_tracing_flush_all(struct upcall_tracing *tracing)
{
    struct upcall_trace_block *block;

    ovs_mutex_lock(&tracing->mutex);
    LIST_FOR_EACH_POP (block, list_node, &tracing->blocks) {
        upcall_trace_block_destroy(block);
    }
    tracing->n_blocks = 0;
    ovs_mutex_unlock(&tracing->mutex);
}

