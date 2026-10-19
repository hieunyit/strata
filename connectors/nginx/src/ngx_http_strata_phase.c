/*
 * PREACCESS handler: transaction setup, request body read, verdict.
 *
 * PREACCESS (not ACCESS) so that "satisfy any" cannot skip the WAF.
 */

#include "ngx_http_strata_module.h"


static ngx_http_strata_ctx_t *ngx_http_strata_create_ctx(ngx_http_request_t *r,
    ngx_http_strata_loc_conf_t *slcf);
static ngx_int_t ngx_http_strata_start_tx(ngx_http_request_t *r,
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

        if (ngx_http_strata_start_tx(r, ctx, slcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
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
    ngx_chain_t            *cl;
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
     * A body read before this location's PREACCESS (e.g. by proxy_pass in a
     * location without strata, then an internal redirect here) never went
     * through the filter: inspect what NGINX kept of it. Parts already in
     * a temporary file are not read here (no I/O in the event loop): the
     * transaction fails and strata_fail_mode applies.
     */

    if (!ctx->body_seen && r->request_body) {
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            ngx_http_strata_body_buf(r, ctx, cl->buf);
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "strata: body read before, inspected from its buffers");
    }

    /*
     * The body filter may never have seen a last buffer, e.g. without
     * Content-Length or with HTTP/2 END_STREAM on HEADERS.
     */

    ngx_http_strata_body_end(r, ctx);

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

    if (!ctx->degraded) {
        ngx_http_strata_breaker_record(r, v->error);
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "strata: verdict action:%uD error:%D id:\"%s\"",
                   v->action, v->error, v->block_id);

    if (v->error != STRATA_OK) {
        ctx->failed = 1;

        /* #98: budget out on a request with findings, policy says block */
        if (v->flags & STRATA_VF_FAIL_CLOSED) {
            ctx->fail_closed = 1;
        }

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

    ctx->r = r;

    ctx->policy = slcf->policy;
    ctx->body_limit = slcf->body_limit;
    ctx->fail_closed = (slcf->fail_mode == NGX_HTTP_STRATA_FAIL_CLOSED);
    ctx->stream = (slcf->body_mode == NGX_HTTP_STRATA_BODY_STREAM);
    ctx->resp_inspect = slcf->response_inspect ? 1 : 0;
    ctx->resp_limit = slcf->response_body_limit;

    ngx_http_set_ctx(r, ctx, ngx_http_strata_module);

    return ctx;
}


static ngx_int_t
ngx_http_strata_start_tx(ngx_http_request_t *r, ngx_http_strata_ctx_t *ctx,
    ngx_http_strata_loc_conf_t *slcf)
{
    ngx_str_t                     identity;
#if (NGX_HTTP_SSL)
    u_char                       *ja4;
#endif
    strata_conn_t                 conn;
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
        || slcf->body_mode == NGX_HTTP_STRATA_BODY_STREAM
        || ngx_http_strata_is_force_shadow(&ctx->policy))
    {
        conn.flags |= STRATA_TXF_FORCE_SHADOW;
    }

    ctx->degraded = ngx_http_strata_breaker_degraded(r);

    if (ctx->degraded) {
        conn.flags |= STRATA_TXF_DEGRADED;
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

    /* the request keeps this bundle mapped until its pool cleanup */

    ctx->bundle = ngx_http_strata_bundle_acquire();
    ctx->bundle_version = ctx->bundle ? ctx->bundle->version : 0;

    ctx->tx = strata_tx_new(ctx->bundle ? ctx->bundle->engine : NULL,
                            ngx_http_strata_str(&ctx->policy), &conn,
                            (uint64_t) slcf->cpu_budget * 1000);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "strata: tx created %p", ctx->tx);

    if (ctx->tx == NULL) {
        /* strata_tx_verdict() reports STRATA_E_INVALID for a NULL tx */
        return NGX_OK;
    }

#if (NGX_HTTP_SSL)
    if (r->connection->ssl && ngx_http_strata_ja4_index != -1) {
        ja4 = SSL_get_ex_data(r->connection->ssl->connection,
                              ngx_http_strata_ja4_index);
        if (ja4 != NULL) {
            (void) strata_tx_set_ja4(ctx->tx,
                                     (strata_str_t) { ja4, STRATA_JA4_LEN });
        }
    }
#endif

    if (ctx->degraded && slcf->breaker_action == NGX_HTTP_STRATA_BREAKER_REJECT)
    {
        /* 503 with an Event ID, whatever strata_fail_mode says */
        (void) strata_tx_fail(ctx->tx, STRATA_E_INTERNAL);
        ctx->fail_closed = 1;
        return NGX_OK;
    }

    /* errors are sticky in the transaction and surface in the verdict */

    (void) strata_tx_request_line(ctx->tx,
                                  ngx_http_strata_str(&r->method_name),
                                  ngx_http_strata_str(&r->unparsed_uri),
                                  ngx_http_strata_str(&r->uri),
                                  ngx_http_strata_str(&r->args),
                                  ngx_http_strata_str(&r->http_protocol));

    return ngx_http_strata_send_headers(r, ctx->tx);
}


static ngx_int_t
ngx_http_strata_send_headers(ngx_http_request_t *r, strata_tx_t *tx)
{
    size_t            n;
    strata_header_t  *hdrs;

    hdrs = ngx_http_strata_headers(r, &r->headers_in.headers, &n);
    if (hdrs == NULL && n) {
        return NGX_ERROR;
    }

    /* an engine error is sticky in the tx and handled with the verdict */

    (void) strata_tx_request_headers(tx, hdrs, n);

    return NGX_OK;
}


/* borrowed views of a header list; NULL with *n != 0 on allocation error */

strata_header_t *
ngx_http_strata_headers(ngx_http_request_t *r, ngx_list_t *list, size_t *n)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    strata_header_t  *hdrs;

    *n = 0;

    for (part = &list->part; part; part = part->next) {
        *n += part->nelts;
    }

    if (*n == 0) {
        return NULL;
    }

    hdrs = ngx_palloc(r->pool, *n * sizeof(strata_header_t));
    if (hdrs == NULL) {
        return NULL;
    }

    *n = 0;

    for (part = &list->part; part; part = part->next) {
        h = part->elts;

        for (i = 0; i < part->nelts; i++) {
            if (h[i].hash == 0) {
                continue;               /* deleted (response headers) */
            }

            hdrs[*n].key = ngx_http_strata_str(&h[i].key);
            hdrs[*n].val = ngx_http_strata_str(&h[i].value);
            (*n)++;
        }
    }

    return hdrs;
}


static void
ngx_http_strata_cleanup(void *data)
{
    ngx_http_strata_ctx_t  *ctx = data;
    uint64_t                engine_us = 0;
    size_t                  len;

    /* runs exactly once, also when the client goes away mid-request */

    if (ctx->tx != NULL) {
        engine_us = strata_tx_time_us(ctx->tx);

        if (!ctx->emitted) {
            if (!ctx->status_sent) {
                uint16_t status = ctx->status ? ctx->status : ctx->verdict.status;
                (void) strata_tx_response_headers(ctx->tx, status, NULL, 0);
                ctx->status_sent = 1;
            }

            len = strata_tx_event(ctx->tx, ngx_http_strata_event_buf,
                                  sizeof(ngx_http_strata_event_buf));
            if (len > 0) {
                ngx_http_strata_event_send(len);
            }
            ctx->emitted = 1;
        }

        /* a replay sample, on the event socket too (W12-N-01) */
        len = strata_tx_sample(ctx->tx, ngx_http_strata_event_buf,
                               sizeof(ngx_http_strata_event_buf));
        if (len > 0 && len <= sizeof(ngx_http_strata_event_buf)) {
            ngx_http_strata_event_send(len);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "strata: tx freed %p", ctx->tx);

        strata_tx_free(ctx->tx);
        ctx->tx = NULL;
    }

    if (!ctx->counted && (ctx->decided || ctx->failed)) {
        ngx_http_strata_metrics_record(ctx, engine_us);
        ctx->counted = 1;
    }

    /* after the tx: the engine must outlive every transaction built on it */

    if (ctx->bundle != NULL) {
        ngx_http_strata_bundle_release(ctx->bundle);
        ctx->bundle = NULL;
    }
}
