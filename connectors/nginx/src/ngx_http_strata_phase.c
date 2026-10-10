/*
 * PREACCESS handler: transaction setup, request body read, verdict.
 *
 * PREACCESS (not ACCESS) so that "satisfy any" cannot skip the WAF.
 */

#include "ngx_http_strata_module.h"


static ngx_http_strata_ctx_t *ngx_http_strata_create_ctx(ngx_http_request_t *r,
    ngx_http_strata_loc_conf_t *slcf);
static void ngx_http_strata_start_tx(ngx_http_request_t *r,
    ngx_http_strata_ctx_t *ctx, ngx_http_strata_loc_conf_t *slcf);
static ngx_int_t ngx_http_strata_send_headers(ngx_http_request_t *r,
    strata_tx_t *tx);
static void ngx_http_strata_body_read(ngx_http_request_t *r);
static ngx_int_t ngx_http_strata_apply_verdict(ngx_http_request_t *r,
    ngx_http_strata_ctx_t *ctx);
static void ngx_http_strata_cleanup(void *data);


#define ngx_http_strata_str(s)  (strata_str_t) { (s)->data, (s)->len }


ngx_int_t
ngx_http_strata_preaccess_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    strata_verdict_t             v;
    ngx_http_strata_ctx_t       *ctx;
    ngx_http_strata_loc_conf_t  *slcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_strata_module);

    if (!slcf->enable) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_strata_get_ctx(r);

    if (ctx == NULL) {
        ctx = ngx_http_strata_create_ctx(r, slcf);
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_strata_start_tx(r, ctx, slcf);
    }

    if (ctx->decided) {
        /* internal redirect: keep the first verdict, do not inspect again */
        return NGX_DECLINED;
    }

    if (ctx->body_state == NGX_HTTP_STRATA_BODY_DONE) {
        return ngx_http_strata_apply_verdict(r, ctx);
    }

    if (ctx->body_state == NGX_HTTP_STRATA_BODY_WAITING) {
        return NGX_DONE;
    }

    strata_tx_verdict(ctx->tx, &v);

    if (v.error != STRATA_OK
        || v.action == STRATA_ACTION_BLOCK
        || !(v.flags & STRATA_VF_NEED_BODY)
        || slcf->body_mode == NGX_HTTP_STRATA_BODY_STREAM)
    {
        /*
         * Decided without the body, or "stream" (shadow only): the body is
         * inspected by the request body filter while the proxy reads it.
         */
        ctx->body_state = NGX_HTTP_STRATA_BODY_DONE;
        return ngx_http_strata_apply_verdict(r, ctx);
    }

    /*
     * ngx_http_read_client_request_body() increments r->main->count and
     * calls the post handler either right away (NGX_OK) or later (NGX_AGAIN).
     * The reference is given back exactly once: by the post handler in the
     * sync case, right below in the async case.
     */

    rc = ngx_http_read_client_request_body(r, ngx_http_strata_body_read);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (rc == NGX_AGAIN) {
        ctx->body_state = NGX_HTTP_STRATA_BODY_WAITING;

        /*
         * Give the reference back now, as the mirror module does: if NGINX
         * fails the body read itself (e.g. 413 on a chunked body), it never
         * calls the post handler and finalizes the request on its own.
         */

        ngx_http_finalize_request(r, NGX_DONE);
        return NGX_DONE;
    }

    /* NGX_OK: the post handler already ran synchronously */

    return ngx_http_strata_apply_verdict(r, ctx);
}


static void
ngx_http_strata_body_read(ngx_http_request_t *r)
{
    ngx_uint_t              waiting;
    ngx_http_strata_ctx_t  *ctx;

    ctx = ngx_http_strata_get_ctx(r);
    if (ctx == NULL) {
        r->main->count--;
        return;
    }

    waiting = (ctx->body_state == NGX_HTTP_STRATA_BODY_WAITING);

    if (!waiting) {
        /* sync: return the reference taken by the read call */
        r->main->count--;
    }

    /*
     * The body filter may never have seen a last buffer, e.g. without
     * Content-Length or with HTTP/2 END_STREAM on HEADERS.
     */

    if (!ctx->body_last) {
        ctx->body_last = 1;
        (void) strata_tx_request_body_chunk(ctx->tx, NULL, 0, 1);
    }

    ctx->body_state = NGX_HTTP_STRATA_BODY_DONE;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "strata: body read, %s", waiting ? "async" : "sync");

    if (waiting) {
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
    }
}


static ngx_int_t
ngx_http_strata_apply_verdict(ngx_http_request_t *r, ngx_http_strata_ctx_t *ctx)
{
    strata_verdict_t  *v;

    v = &ctx->verdict;

    strata_tx_verdict(ctx->tx, v);
    v->block_id[STRATA_BLOCK_ID_SIZE - 1] = '\0';

    ctx->decided = 1;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "strata: verdict action:%uD error:%D id:\"%s\"",
                   v->action, v->error, v->block_id);

    if (v->error != STRATA_OK) {
        ctx->failed = 1;

        if (v->error != STRATA_E_BUNDLE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "strata: engine error %D, event id %s, fail mode %s",
                          v->error, v->block_id,
                          ctx->fail_closed ? "closed" : "open");
        }

        if (ctx->fail_closed) {
            return ngx_http_strata_send_block(r, ctx,
                                              NGX_HTTP_SERVICE_UNAVAILABLE);
        }

        return NGX_DECLINED;
    }

    if (v->action == STRATA_ACTION_BLOCK) {
        return ngx_http_strata_send_block(r, ctx,
                                          v->status ? v->status
                                                    : NGX_HTTP_FORBIDDEN);
    }

    /* TODO(challenge): not produced by the stub; treated as allow */

    return NGX_DECLINED;
}


ngx_http_strata_ctx_t *
ngx_http_strata_get_ctx(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t     *cln;
    ngx_http_strata_ctx_t  *ctx;

    r = r->main;

    ctx = ngx_http_get_module_ctx(r, ngx_http_strata_module);
    if (ctx != NULL) {
        return ctx;
    }

    /*
     * Internal redirects clear r->ctx but keep r->pool: find the context
     * through its pool cleanup. A new request always has a new pool.
     */

    for (cln = r->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_strata_cleanup) {
            ctx = cln->data;
            ngx_http_set_ctx(r, ctx, ngx_http_strata_module);

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "strata: context restored");
            return ctx;
        }
    }

    return NULL;
}


static ngx_http_strata_ctx_t *
ngx_http_strata_create_ctx(ngx_http_request_t *r,
    ngx_http_strata_loc_conf_t *slcf)
{
    ngx_pool_cleanup_t     *cln;
    ngx_http_strata_ctx_t  *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_strata_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_strata_cleanup;
    cln->data = ctx;

    ctx->policy = slcf->policy;
    ctx->body_limit = slcf->body_limit;
    ctx->fail_closed = (slcf->fail_mode == NGX_HTTP_STRATA_FAIL_CLOSED);

    ngx_http_set_ctx(r, ctx, ngx_http_strata_module);

    return ctx;
}


static void
ngx_http_strata_start_tx(ngx_http_request_t *r, ngx_http_strata_ctx_t *ctx,
    ngx_http_strata_loc_conf_t *slcf)
{
    ngx_str_t                     identity;
    strata_conn_t                 conn;
    strata_engine_t              *engine;
    ngx_http_variable_value_t    *vv;
    ngx_http_strata_main_conf_t  *smcf;

    smcf = ngx_http_get_module_main_conf(r, ngx_http_strata_module);

    ngx_memzero(&conn, sizeof(strata_conn_t));

    conn.client_addr = ngx_http_strata_str(&r->connection->addr_text);
    conn.client_port = (uint16_t) ngx_inet_get_port(r->connection->sockaddr);
    conn.node_id = ngx_http_strata_str(&smcf->node_id);

#if (NGX_HTTP_SSL)
    if (r->connection->ssl) {
        conn.flags |= STRATA_TXF_TLS;
    }
#endif

#if (NGX_HTTP_V2)
    if (r->stream) {
        conn.flags |= STRATA_TXF_HTTP2;
    }
#endif

    if (r->http_version == NGX_HTTP_VERSION_30) {
        conn.flags |= STRATA_TXF_HTTP3;
    }

    if (slcf->mode == NGX_HTTP_STRATA_MODE_SHADOW
        || slcf->body_mode == NGX_HTTP_STRATA_BODY_STREAM)
    {
        conn.flags |= STRATA_TXF_FORCE_SHADOW;
    }

    if (slcf->identity
        && ngx_http_complex_value(r, slcf->identity, &identity) == NGX_OK)
    {
        conn.identity = ngx_http_strata_str(&identity);
    }

    vv = ngx_http_get_indexed_variable(r, smcf->request_id_index);
    if (vv && !vv->not_found) {
        conn.request_id = (strata_str_t) { vv->data, vv->len };
    }

    engine = smcf->bundle ? smcf->bundle->engine : NULL;

    ctx->tx = strata_tx_new(engine, ngx_http_strata_str(&ctx->policy), &conn,
                            (uint64_t) slcf->cpu_budget * 1000);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "strata: tx created %p", ctx->tx);

    if (ctx->tx == NULL) {
        /* strata_tx_verdict() reports STRATA_E_INVALID for a NULL tx */
        return;
    }

    /* errors are sticky in the transaction and surface in the verdict */

    (void) strata_tx_request_line(ctx->tx,
                                  ngx_http_strata_str(&r->method_name),
                                  ngx_http_strata_str(&r->unparsed_uri),
                                  ngx_http_strata_str(&r->uri),
                                  ngx_http_strata_str(&r->args),
                                  ngx_http_strata_str(&r->http_protocol));

    (void) ngx_http_strata_send_headers(r, ctx->tx);
}


static ngx_int_t
ngx_http_strata_send_headers(ngx_http_request_t *r, strata_tx_t *tx)
{
    ngx_uint_t        i, n;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    strata_header_t  *hdrs;

    n = 0;

    for (part = &r->headers_in.headers.part; part; part = part->next) {
        n += part->nelts;
    }

    hdrs = NULL;

    if (n) {
        hdrs = ngx_palloc(r->pool, n * sizeof(strata_header_t));
        if (hdrs == NULL) {
            return NGX_ERROR;
        }
    }

    n = 0;

    for (part = &r->headers_in.headers.part; part; part = part->next) {
        h = part->elts;

        for (i = 0; i < part->nelts; i++) {
            hdrs[n].key = ngx_http_strata_str(&h[i].key);
            hdrs[n].val = ngx_http_strata_str(&h[i].value);
            n++;
        }
    }

    return strata_tx_request_headers(tx, hdrs, n) == STRATA_OK
           ? NGX_OK : NGX_ERROR;
}


static void
ngx_http_strata_cleanup(void *data)
{
    ngx_http_strata_ctx_t  *ctx = data;

    /* runs exactly once, also when the client goes away mid-request */

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "strata: tx freed %p", ctx->tx);

    strata_tx_free(ctx->tx);
    ctx->tx = NULL;
}
