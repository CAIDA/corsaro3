

#include "config.h"

#include "libcorsaro.h"
#include "libcorsaro_plugin.h"
#include "libcorsaro_common.h"
#include "corsaro_null.h"

#define CORSARO_NULL_MAGIC 0x6e756c6c
#define PLUGIN_NAME "nullplugin"

static corsaro_plugin_t corsaro_null_plugin = {

    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_NULL,
    CORSARO_NULL_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_null),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_null),
    CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_null),
    CORSARO_PLUGIN_GENERATE_TAIL

};

corsaro_plugin_t *corsaro_null_alloc(void) {
    return &corsaro_null_plugin;
}

int corsaro_null_parse_config(corsaro_plugin_t *p, yaml_document_t *doc,
        yaml_node_t *options) {
    return 0;
}

int corsaro_null_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt) {

    return 0;
}

void corsaro_null_destroy_self(corsaro_plugin_t *p) {
    return;
}

void *corsaro_null_init_processing(corsaro_plugin_t *p, int threadid) {

    uint64_t *state;

    state = (uint64_t *)calloc(1, sizeof(uint64_t));
    return state;

}

int corsaro_null_halt_processing(corsaro_plugin_t *p, void *local) {

    uint64_t *state = (uint64_t *)local;

    if (state) {
        free(state);
    }

}

char *corsaro_null_derive_output_name(corsaro_plugin_t *p, void *local,
        uint32_t timestamp, int threadid) {

    return (char *)"/tmp/doesnotmatter";

}

int corsaro_null_start_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_start) {

    uint64_t *state = (uint64_t *)local;
    *state = 0;
}

void *corsaro_null_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end, uint8_t complete) {

    uint64_t *state = (uint64_t *)local;
    corsaro_log(p->logger, "processed %lu packets this interval", *state);
    return NULL;
}

int corsaro_null_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {

    uint64_t *state = (uint64_t *)local;
    (*state) += 1;
    return 0;
}

void *corsaro_null_init_merging(corsaro_plugin_t *p, int sources) {

    uint64_t *state;

    state = (uint64_t *)calloc(1, sizeof(uint64_t));
    return state;
}

int corsaro_null_halt_merging(corsaro_plugin_t *p, void *local) {

    uint64_t *state = (uint64_t *)local;
    if (state) {
        free(state);
    }
    return 0;
}

int corsaro_null_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin, void *tagsock) {

    return 0;
}

int corsaro_null_rotate_output(corsaro_plugin_t *p, void *local) {

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
