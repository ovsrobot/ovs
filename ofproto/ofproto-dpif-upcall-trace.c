#include <config.h>

#include "ofproto-dpif-upcall-trace.h"

#include <openvswitch/dynamic-string.h>
#include <openvswitch/ofp-flow.h>
#include <openvswitch/ofp-port.h>
#include <openvswitch/vlog.h>
#include "ofproto-dpif.h"

VLOG_DEFINE_THIS_MODULE(upcall_trace);

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
