/*
 * Response path (W06-N-01): a separate HTTP filter module, ordered right
 * before ngx_http_copy_filter_module, so that its body filter runs after
 * the copy filter (file buffers are read into memory once
 * r->filter_need_in_memory is set) and before gzip, sub_filter and SSI
 * (it sees the body as the upstream or the file produced it).
 *
 * Header filter: status and headers go to libstrata; the body is inspected
 * only when the verdict asks for it (STRATA_VF_NEED_RESPONSE) and
 * strata_response_inspect is on, and not when the upstream already
 * compressed it (Content-Encoding), which is logged instead.
 *
 * Body filter: up to strata_response_body_limit bytes go to libstrata. The
 * original buffers are never modified: when libstrata rewrites (data
 * guard), the bytes are copied into new pool buffers that carry the flags
 * of the original (last_buf, last_in_chain, flush, sync), and the original
 * is marked consumed. The copies are reused once sent (free/busy chains),
 * so memory follows the buffer sizes, not the response size or the limit;
 * beyond the limit buffers pass untouched.
 */

#include "ngx_http_strata_module.h"


static ngx_int_t ngx_http_strata_response_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_strata_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_strata_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);


static ngx_http_module_t  ngx_http_strata_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_strata_response_init,         /* postconfiguration */
    NULL, NULL, NULL, NULL, NULL, NULL
};


ngx_module_t  ngx_http_strata_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_strata_filter_module_ctx,    /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_strata_response_init(ngx_conf_t *cf)
{
    ngx_http_strata_main_conf_t  *smcf;

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_strata_module);
    if (smcf == NULL || !smcf->enabled) {
        return NGX_OK;
    }

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_strata_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_strata_body_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_strata_header_filter(ngx_http_request_t *r)
{
    size_t                  n;
    strata_header_t        *hdrs;
    strata_verdict_t        v;
    ngx_http_strata_ctx_t  *ctx;

    if (r != r->main) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_strata_get_ctx(r);

    if (ctx == NULL || ctx->tx == NULL || ctx->own_response) {
        return ngx_http_next_header_filter(r);
    }

    hdrs = ngx_http_strata_headers(r, &r->headers_out.headers, &n);
    if (hdrs == NULL && n) {
        return NGX_ERROR;
    }

    (void) strata_tx_response_headers(ctx->tx,
                                      (uint16_t) r->headers_out.status,
                                      hdrs, n);

    strata_tx_verdict(ctx->tx, &v);

    if (!(v.flags & STRATA_VF_NEED_RESPONSE) || !ctx->resp_inspect
        || r->header_only)
    {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_encoding
        && r->headers_out.content_encoding->value.len
        && !(r->headers_out.content_encoding->value.len == 8
             && ngx_strncasecmp(r->headers_out.content_encoding->value.data,
                                (u_char *) "identity", 8) == 0))
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "strata: response body compressed by the upstream "
                      "(Content-Encoding: %V), not inspected",
                      &r->headers_out.content_encoding->value);
        return ngx_http_next_header_filter(r);
    }

    /* file buffers are read into memory by the copy filter for us */

    r->filter_need_in_memory = 1;
    ctx->resp_active = 1;

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_strata_out(ngx_http_request_t *r, ngx_chain_t ***ll, ngx_buf_t *b)
{
    ngx_chain_t  *cl;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;
    **ll = cl;
    *ll = &cl->next;

    return NGX_OK;
}


/*
 * A buffer with "len" bytes from p and, if asked, b's flags: a free one of
 * ours when large enough, else a new one from the pool.
 */

static ngx_buf_t *
ngx_http_strata_copy_buf(ngx_http_request_t *r, ngx_http_strata_ctx_t *ctx,
    u_char *p, size_t len, ngx_buf_t *b, ngx_uint_t flags)
{
    ngx_buf_t    *nb;
    ngx_chain_t  *cl, **ll;

    nb = NULL;

    for (ll = &ctx->resp_free; *ll; ll = &(*ll)->next) {
        cl = *ll;

        if ((size_t) (cl->buf->end - cl->buf->start) >= len) {
            nb = cl->buf;
            *ll = cl->next;
            ngx_free_chain(r->pool, cl);
            break;
        }
    }

    if (nb == NULL) {
        nb = ngx_create_temp_buf(r->pool, ngx_max(len, 1));
        if (nb == NULL) {
            return NULL;
        }

        nb->tag = (ngx_buf_tag_t) &ngx_http_strata_filter_module;
    }

    nb->pos = nb->start;
    nb->last = ngx_cpymem(nb->pos, p, len);

    nb->last_buf = flags ? b->last_buf : 0;
    nb->last_in_chain = flags ? b->last_in_chain : 0;
    nb->flush = flags ? b->flush : 0;
    nb->sync = flags ? b->sync : 0;

    return nb;
}


static ngx_int_t
ngx_http_strata_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                  size, n;
    ngx_int_t               rc, last, mem, whole;
    ngx_buf_t              *b, *nb;
    ngx_chain_t            *cl, *out, **ll;
    strata_buf_t            rw;
    ngx_http_strata_ctx_t  *ctx;

    if (r != r->main || in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_strata_get_ctx(r);

    if (ctx == NULL || !ctx->resp_active || ctx->resp_done
        || ctx->tx == NULL)
    {
        return ngx_http_next_body_filter(r, in);
    }

    out = NULL;
    ll = &out;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;

        if (ctx->resp_done) {
            /* past the limit or the end: untouched */
            if (ngx_http_strata_out(r, &ll, b) != NGX_OK) {
                return NGX_ERROR;
            }
            continue;
        }

        mem = ngx_buf_in_memory(b);

        if (!mem && ngx_buf_size(b) > 0) {
            /* should not happen with filter_need_in_memory */
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "strata: response buffer not in memory, "
                          "rest of the response not inspected");
        }

        size = mem ? (size_t) (b->last - b->pos) : 0;
        n = ngx_min(size, ctx->resp_limit - ctx->resp_inspected);
        last = (!mem && ngx_buf_size(b) > 0) || b->last_buf
               || ctx->resp_inspected + n >= ctx->resp_limit;

        if (size == 0 && !last) {
            /* flush, sync or empty buffer: nothing for libstrata */
            if (ngx_http_strata_out(r, &ll, b) != NGX_OK) {
                return NGX_ERROR;
            }
            continue;
        }

        rw.ptr = NULL;
        (void) strata_tx_response_body_chunk(ctx->tx, n ? b->pos : NULL, n,
                                             last ? 1 : 0, &rw);
        ctx->resp_inspected += n;
        ctx->resp_done = last ? 1 : 0;

        /*
         * Rewritten: a copy carries the data. If all of b was inspected, the
         * copy takes b's flags and b is consumed; otherwise (limit reached,
         * or b not in memory) the rest of b follows the copy untouched.
         */

        whole = (rw.ptr != NULL && mem && n == size);

        if (rw.ptr && (rw.len || (whole && (b->last_buf || b->last_in_chain
                                            || b->flush || b->sync))))
        {
            nb = ngx_http_strata_copy_buf(r, ctx, rw.ptr, rw.len, b, whole);
            if (nb == NULL || ngx_http_strata_out(r, &ll, nb) != NGX_OK) {
                strata_buf_free(&rw);
                return NGX_ERROR;
            }
        }

        if (rw.ptr) {
            b->pos += n;
        }

        strata_buf_free(&rw);

        if (!whole && ngx_http_strata_out(r, &ll, b) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    rc = ngx_http_next_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &ctx->resp_free, &ctx->resp_busy, &out,
                            (ngx_buf_tag_t) &ngx_http_strata_filter_module);

    return rc;
}
