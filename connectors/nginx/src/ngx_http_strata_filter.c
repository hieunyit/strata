/*
 * Request body filter: every chunk, already de-chunked by NGINX (exactly what
 * the upstream will receive), goes to libstrata up to
 * strata_request_body_limit bytes.
 *
 * It runs before NGINX's save filter, so chunks are still in memory even
 * when the body is then spooled to a temporary file. Bytes over the limit
 * are reported to libstrata (the policy's "oversize" decides); a buffer
 * that is not in memory is never skipped silently: the transaction is
 * failed (STRATA_E_INCOMPLETE) and strata_fail_mode applies.
 *
 * TODO(response): header and body filters for response inspection.
 */

#include "ngx_http_strata_module.h"


static ngx_int_t ngx_http_strata_request_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);


static ngx_http_request_body_filter_pt  ngx_http_next_request_body_filter;


ngx_int_t
ngx_http_strata_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_strata_request_body_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_strata_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t              *b;
    ngx_chain_t            *cl;
    ngx_http_strata_ctx_t  *ctx;

    if (r != r->main) {
        return ngx_http_next_request_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_strata_module);

    if (ctx == NULL || ctx->tx == NULL || ctx->body_last) {
        return ngx_http_next_request_body_filter(r, in);
    }

    ctx->body_seen = 1;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;

        ngx_http_strata_body_buf(r, ctx, b);

        if (b->last_buf) {
            ngx_http_strata_body_end(r, ctx);
            break;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "strata: request body inspected:%uz last:%ud",
                   ctx->body_inspected, ctx->body_last);

    return ngx_http_next_request_body_filter(r, in);
}


/* one body buffer: inspected up to the limit, counted beyond it */

void
ngx_http_strata_body_buf(ngx_http_request_t *r, ngx_http_strata_ctx_t *ctx,
    ngx_buf_t *b)
{
    size_t  size, n;

    if (!ngx_buf_in_memory(b)) {
        if (ngx_buf_size(b) > 0 && !ctx->body_unread) {
            ctx->body_unread = 1;
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "strata: request body buffer not in memory, "
                          "not inspected; applying strata_fail_mode");
        }
        return;
    }

    size = (size_t) (b->last - b->pos);
    n = 0;

    if (ctx->body_inspected < ctx->body_limit) {
        n = ngx_min(size, ctx->body_limit - ctx->body_inspected);

        if (n) {
            (void) strata_tx_request_body_chunk(ctx->tx, b->pos, n, 0);
            ctx->body_inspected += n;
        }
    }

    ctx->body_skipped += size - n;
}


/* end of the body: report what was not inspected, then the last chunk */

void
ngx_http_strata_body_end(ngx_http_request_t *r, ngx_http_strata_ctx_t *ctx)
{
    if (ctx->body_last) {
        return;
    }

    ctx->body_last = 1;

    if (ctx->body_skipped) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "strata: request body over the limit by %uL bytes",
                       ctx->body_skipped);
        (void) strata_tx_request_body_skipped(ctx->tx, ctx->body_skipped);
    }

    if (ctx->body_unread) {
        (void) strata_tx_fail(ctx->tx, STRATA_E_INCOMPLETE);
    }

    (void) strata_tx_request_body_chunk(ctx->tx, NULL, 0, 1);
}
