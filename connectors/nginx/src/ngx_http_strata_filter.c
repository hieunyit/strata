/*
 * Request body filter: every chunk, already de-chunked by NGINX (exactly what
 * the upstream will receive), goes to libstrata up to
 * strata_request_body_limit bytes.
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
    size_t                  size;
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

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;

        if (ngx_buf_in_memory(b) && ctx->body_inspected < ctx->body_limit) {
            size = ngx_min((size_t) (b->last - b->pos),
                           ctx->body_limit - ctx->body_inspected);

            if (size) {
                (void) strata_tx_request_body_chunk(ctx->tx, b->pos, size, 0);
                ctx->body_inspected += size;
            }
        }

        if (b->last_buf) {
            ctx->body_last = 1;
            (void) strata_tx_request_body_chunk(ctx->tx, NULL, 0, 1);
            break;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "strata: request body inspected:%uz last:%ud",
                   ctx->body_inspected, ctx->body_last);

    return ngx_http_next_request_body_filter(r, in);
}
