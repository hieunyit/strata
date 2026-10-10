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

#define NGX_HTTP_STRATA_BUNDLE_FILE    "current.sbn"
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


typedef struct {
    strata_engine_t            *engine;
    u_char                     *base;
    size_t                      len;
} ngx_http_strata_bundle_t;


typedef struct {
    ngx_str_t                   control_file;
    ngx_str_t                   bundle_dir;
    ngx_str_t                   pubkey_file;
    ngx_msec_t                  bundle_check;
    ngx_str_t                   node_id;
    ngx_str_t                   event_socket;

    ngx_flag_t                  enabled;        /* "strata on" somewhere */
    ngx_int_t                   request_id_index;
    ngx_http_strata_bundle_t   *bundle;         /* NULL: no bundle loaded */
    ngx_http_strata_page_t     *default_page;
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
    ngx_str_t                   policy;
    size_t                      body_limit;
    size_t                      body_inspected;
    strata_verdict_t            verdict;

    unsigned                    body_state:2;
    unsigned                    body_last:1;    /* final chunk sent */
    unsigned                    decided:1;      /* verdict applied */
    unsigned                    failed:1;       /* engine error */
    unsigned                    fail_closed:1;
} ngx_http_strata_ctx_t;


extern ngx_module_t  ngx_http_strata_module;


/* ngx_http_strata_phase.c */
ngx_int_t ngx_http_strata_preaccess_handler(ngx_http_request_t *r);
ngx_http_strata_ctx_t *ngx_http_strata_get_ctx(ngx_http_request_t *r);

/* ngx_http_strata_filter.c */
ngx_int_t ngx_http_strata_filter_init(ngx_conf_t *cf);

/* ngx_http_strata_block.c */
ngx_int_t ngx_http_strata_send_block(ngx_http_request_t *r,
    ngx_http_strata_ctx_t *ctx, ngx_uint_t status);
ngx_http_strata_page_t *ngx_http_strata_page_compile(ngx_pool_t *pool,
    ngx_str_t *text);

/* ngx_http_strata_bundle.c */
ngx_int_t ngx_http_strata_bundle_init(ngx_conf_t *cf,
    ngx_http_strata_main_conf_t *smcf);

/* ngx_http_strata_vars.c */
ngx_int_t ngx_http_strata_add_variables(ngx_conf_t *cf);


#endif /* _NGX_HTTP_STRATA_MODULE_H_INCLUDED_ */
