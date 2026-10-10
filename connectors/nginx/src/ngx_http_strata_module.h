/*
 * ngx_http_strata_module — thin NGINX connector for libstrata.
 *
 * The C side never parses input: it hands pointers and lengths taken from
 * NGINX structures to libstrata and enforces the verdict.
 */

#ifndef _NGX_HTTP_STRATA_MODULE_H_INCLUDED_
#define _NGX_HTTP_STRATA_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#endif

#include "strata.h"


#define NGX_HTTP_STRATA_MODE_INHERIT   0
#define NGX_HTTP_STRATA_MODE_SHADOW    1

#define NGX_HTTP_STRATA_FAIL_OPEN      0
#define NGX_HTTP_STRATA_FAIL_CLOSED    1

#define NGX_HTTP_STRATA_BODY_BUFFER    0
#define NGX_HTTP_STRATA_BODY_STREAM    1

#define NGX_HTTP_STRATA_BODY_NONE      0
#define NGX_HTTP_STRATA_BODY_WAITING   1
#define NGX_HTTP_STRATA_BODY_DONE      2

/* $strata_action value when the engine failed (beyond STRATA_ACTION_*) */
#define NGX_HTTP_STRATA_ACTION_ERROR   4

#define NGX_HTTP_STRATA_CTL_SIZE       4096
#define NGX_HTTP_STRATA_CTL_NAME_MAX   255
#define NGX_HTTP_STRATA_PAGE_MAX       65536

/* placeholders of the block page template */
#define NGX_HTTP_STRATA_PAGE_TEXT      0
#define NGX_HTTP_STRATA_PAGE_BLOCK_ID  1
#define NGX_HTTP_STRATA_PAGE_TIME      2
#define NGX_HTTP_STRATA_PAGE_CONTACT   3


typedef struct {
    ngx_str_t                   text;
    ngx_uint_t                  type;
} ngx_http_strata_page_part_t;


/* block page template, split at load time so requests only copy */
typedef struct {
    ngx_array_t                 parts;    /* ngx_http_strata_page_part_t */
    size_t                      text_len;
    ngx_uint_t                  nvars;
} ngx_http_strata_page_t;


/*
 * A mapped bundle. "refs" counts the requests using it, plus one while it is
 * the worker's current bundle; the last release unmaps it.
 */
typedef struct {
    strata_engine_t            *engine;
    u_char                     *base;
    size_t                      len;
    uint64_t                    version;
    ngx_http_strata_page_t     *page;           /* default block page from
                                                   the bundle, or NULL */
    ngx_str_t                   contact;        /* {{support_contact}} */
    ngx_pool_t                 *pool;           /* worker-loaded: page parts */
    ngx_uint_t                  refs;
    unsigned                    heap:1;      /* worker-loaded, ngx_alloc'd */
    unsigned                    unmapped:1;
} ngx_http_strata_bundle_t;


/* a location with "strata_request_body_mode stream" (shadow only) */
typedef struct {
    ngx_str_t                   policy;
    ngx_str_t                   location;
} ngx_http_strata_stream_loc_t;


typedef struct {
    ngx_str_t                   control_file;
    ngx_str_t                   bundle_dir;
    ngx_str_t                   pubkey_file;
    ngx_msec_t                  bundle_check;
    ngx_str_t                   node_id;
    ngx_str_t                   event_socket;

    ngx_flag_t                  enabled;        /* "strata on" somewhere */
    ngx_int_t                   request_id_index;
    ngx_http_strata_bundle_t   *bundle;         /* mapped by the master */
    uint64_t                    generation;     /* control file generation
                                                   of that bundle */
    u_char                      pubkey[STRATA_PUBKEY_LEN];
    ngx_http_strata_page_t     *default_page;
    ngx_array_t                *stream_locs;    /* ngx_http_strata_stream_loc_t */
#if (NGX_THREADS)
    ngx_thread_pool_t          *thread_pool;
#endif
} ngx_http_strata_main_conf_t;


typedef struct {
    ngx_flag_t                  enable;
    ngx_str_t                   policy;
    ngx_uint_t                  mode;
    ngx_uint_t                  fail_mode;
    ngx_uint_t                  body_mode;
    size_t                      body_limit;
    ngx_flag_t                  response_inspect;
    size_t                      response_body_limit;
    ngx_http_complex_value_t   *identity;
    ngx_http_strata_page_t     *block_page;
    ngx_msec_t                  cpu_budget;
} ngx_http_strata_loc_conf_t;


/*
 * Lives in r->pool and is registered as a pool cleanup, so it survives
 * internal redirects (which wipe r->ctx) and is found again from there.
 */
typedef struct {
    strata_tx_t                *tx;
    ngx_http_strata_bundle_t   *bundle;         /* reference held */
    uint64_t                    bundle_version; /* 0: no bundle */
    ngx_str_t                   policy;
    size_t                      body_limit;
    size_t                      body_inspected;
    uint64_t                    body_skipped;   /* over body_limit */
    size_t                      resp_limit;
    size_t                      resp_inspected;
    ngx_chain_t                *resp_free;      /* our copies, reusable */
    ngx_chain_t                *resp_busy;      /* our copies, in flight */
    strata_verdict_t            verdict;

    unsigned                    body_state:2;
    unsigned                    body_last:1;    /* final chunk sent */
    unsigned                    decided:1;      /* verdict applied */
    unsigned                    failed:1;       /* engine error */
    unsigned                    fail_closed:1;
    unsigned                    stream:1;       /* body inspected after
                                                   the verdict (shadow) */
    unsigned                    body_seen:1;    /* the filter got the body */
    unsigned                    body_unread:1;  /* a part could not be
                                                   passed (not in memory) */
    unsigned                    resp_inspect:1; /* strata_response_inspect */
    unsigned                    resp_active:1;  /* body goes to libstrata */
    unsigned                    resp_done:1;    /* limit or end reached */
    unsigned                    own_response:1; /* our block page */
} ngx_http_strata_ctx_t;


extern ngx_module_t  ngx_http_strata_module;
extern ngx_module_t  ngx_http_strata_filter_module;


/* ngx_http_strata_phase.c */
ngx_int_t ngx_http_strata_preaccess_handler(ngx_http_request_t *r);
ngx_http_strata_ctx_t *ngx_http_strata_get_ctx(ngx_http_request_t *r);
strata_header_t *ngx_http_strata_headers(ngx_http_request_t *r,
    ngx_list_t *list, size_t *n);

/* ngx_http_strata_filter.c */
ngx_int_t ngx_http_strata_filter_init(ngx_conf_t *cf);
void ngx_http_strata_body_buf(ngx_http_request_t *r,
    ngx_http_strata_ctx_t *ctx, ngx_buf_t *b);
void ngx_http_strata_body_end(ngx_http_request_t *r,
    ngx_http_strata_ctx_t *ctx);

/* ngx_http_strata_block.c */
ngx_int_t ngx_http_strata_send_block(ngx_http_request_t *r,
    ngx_http_strata_ctx_t *ctx, ngx_uint_t status);
ngx_http_strata_page_t *ngx_http_strata_page_compile(ngx_pool_t *pool,
    ngx_str_t *text);

/* ngx_http_strata_bundle.c */
ngx_int_t ngx_http_strata_bundle_init(ngx_conf_t *cf,
    ngx_http_strata_main_conf_t *smcf);
ngx_int_t ngx_http_strata_bundle_init_process(ngx_cycle_t *cycle);
void ngx_http_strata_bundle_exit_process(ngx_cycle_t *cycle);
ngx_http_strata_bundle_t *ngx_http_strata_bundle_acquire(void);
ngx_uint_t ngx_http_strata_check_stream(ngx_log_t *log, ngx_uint_t level,
    ngx_http_strata_main_conf_t *smcf, strata_engine_t *engine);
void ngx_http_strata_bundle_release(ngx_http_strata_bundle_t *bundle);

/* ngx_http_strata_vars.c */
ngx_int_t ngx_http_strata_add_variables(ngx_conf_t *cf);


#endif /* _NGX_HTTP_STRATA_MODULE_H_INCLUDED_ */
