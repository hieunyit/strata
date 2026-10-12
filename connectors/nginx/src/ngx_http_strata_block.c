/*
 * Block response: HTML (template) or JSON, with X-Strata-Block-Id.
 *
 * The page never reflects request data: only the Block ID, the time and the
 * support contact are substituted.
 */

#include "ngx_http_strata_module.h"


static ngx_buf_t *ngx_http_strata_render(ngx_http_request_t *r,
    ngx_http_strata_page_t *page, ngx_str_t *id, ngx_str_t *contact);
static ngx_int_t ngx_http_strata_add_header(ngx_http_request_t *r,
    ngx_str_t *key, ngx_str_t *value);


static ngx_str_t  ngx_http_strata_vars[] = {
    ngx_null_string,
    ngx_string("{{block_id}}"),
    ngx_string("{{time}}"),
    ngx_string("{{support_contact}}"),
};


ngx_int_t
ngx_http_strata_send_block(ngx_http_request_t *r, ngx_http_strata_ctx_t *ctx,
    ngx_uint_t status)
{
    size_t                        len;
    ngx_int_t                     rc;
    ngx_str_t                     id, key, value, contact;
    ngx_buf_t                    *b;
    ngx_chain_t                   out;
    ngx_table_elt_t              *server;
    ngx_http_strata_page_t       *page;
    ngx_http_strata_loc_conf_t   *slcf;
    ngx_http_strata_main_conf_t  *smcf;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    /* the response filters must not inspect our own block page */
    ctx->own_response = 1;
    ctx->status = (uint16_t) status;

    id.data = (u_char *) ctx->verdict.block_id;
    id.len = ngx_strlen(id.data);

    if (ctx->verdict.flags & STRATA_VF_JSON) {
        len = sizeof("{\"error\":\"blocked\",\"block_id\":\"\"}") - 1 + id.len;

        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->last = ngx_cpymem(b->last, "{\"error\":\"blocked\",\"block_id\":\"",
                             sizeof("{\"error\":\"blocked\",\"block_id\":\"")
                             - 1);
        b->last = ngx_cpymem(b->last, id.data, id.len);
        b->last = ngx_cpymem(b->last, "\"}", 2);

        ngx_str_set(&r->headers_out.content_type, "application/json");

    } else {
        slcf = ngx_http_get_module_loc_conf(r, ngx_http_strata_module);
        smcf = ngx_http_get_module_main_conf(r, ngx_http_strata_module);

        /* local override, then the bundle's default, then the built-in */

        page = slcf->block_page;
        if (page == NULL && ctx->bundle) {
            page = ctx->bundle->page;
        }
        if (page == NULL) {
            page = smcf->default_page;
        }

        if (ctx->bundle) {
            contact = ctx->bundle->contact;
        } else {
            ngx_str_set(&contact, ""); /* never NULL: copied with memcpy */
        }

        b = ngx_http_strata_render(r, page, &id, &contact);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_str_set(&r->headers_out.content_type, "text/html; charset=utf-8");
    }

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;
    r->headers_out.status = status;
    r->headers_out.content_length_n = b->last - b->pos;

    if (id.len) {
        ngx_str_set(&key, "X-Strata-Block-Id");
        if (ngx_http_strata_add_header(r, &key, &id) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_str_set(&key, "Cache-Control");
    ngx_str_set(&value, "no-store");
    if (ngx_http_strata_add_header(r, &key, &value) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* a present but hidden (hash == 0) Server header suppresses the default */

    server = ngx_list_push(&r->headers_out.headers);
    if (server == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    server->hash = 0;
    server->next = NULL;
    ngx_str_set(&server->key, "Server");
    ngx_str_null(&server->value);
    r->headers_out.server = server;

    rc = ngx_http_send_header(r);

    if (rc != NGX_ERROR && rc <= NGX_OK && !r->header_only) {
        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;

        out.buf = b;
        out.next = NULL;

        rc = ngx_http_output_filter(r, &out);
    }

    /*
     * Outside the content phase NGX_OK would mean "run the next phase":
     * finalize here and stop the phase engine.
     */

    ngx_http_finalize_request(r, rc);

    return NGX_DONE;
}


static ngx_buf_t *
ngx_http_strata_render(ngx_http_request_t *r, ngx_http_strata_page_t *page,
    ngx_str_t *id, ngx_str_t *contact)
{
    size_t                        len;
    ngx_str_t                     time, *s;
    ngx_buf_t                    *b;
    ngx_uint_t                    i;
    ngx_http_strata_page_part_t  *part;

    time = ngx_cached_http_log_iso8601;

    /* each placeholder expands to at most the longest substitution */

    len = page->text_len
          + page->nvars * ngx_max(ngx_max(id->len, time.len), contact->len);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    part = page->parts.elts;

    for (i = 0; i < page->parts.nelts; i++) {

        switch (part[i].type) {

        case NGX_HTTP_STRATA_PAGE_BLOCK_ID:
            s = id;
            break;

        case NGX_HTTP_STRATA_PAGE_TIME:
            s = &time;
            break;

        case NGX_HTTP_STRATA_PAGE_CONTACT:
            s = contact;
            break;

        default: /* NGX_HTTP_STRATA_PAGE_TEXT */
            s = &part[i].text;
            break;
        }

        if ((size_t) (b->end - b->last) < s->len) {
            return NULL;
        }

        b->last = ngx_cpymem(b->last, s->data, s->len);
    }

    return b;
}


static ngx_int_t
ngx_http_strata_add_header(ngx_http_request_t *r, ngx_str_t *key,
    ngx_str_t *value)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->next = NULL;
    h->key = *key;
    h->value = *value;

    return NGX_OK;
}


/* splits a template at its placeholders; runs at configuration time */

ngx_http_strata_page_t *
ngx_http_strata_page_compile(ngx_pool_t *pool, ngx_str_t *text)
{
    u_char                       *p, *start, *end;
    ngx_uint_t                    type;
    ngx_http_strata_page_t       *page;
    ngx_http_strata_page_part_t  *part;

    page = ngx_pcalloc(pool, sizeof(ngx_http_strata_page_t));
    if (page == NULL) {
        return NULL;
    }

    if (ngx_array_init(&page->parts, pool, 8,
                       sizeof(ngx_http_strata_page_part_t))
        != NGX_OK)
    {
        return NULL;
    }

    start = text->data;
    end = text->data + text->len;
    p = start;

    while (p < end) {

        type = NGX_HTTP_STRATA_PAGE_TEXT;

        if (*p == '{') {
            for (type = NGX_HTTP_STRATA_PAGE_BLOCK_ID;
                 type <= NGX_HTTP_STRATA_PAGE_CONTACT;
                 type++)
            {
                if ((size_t) (end - p) >= ngx_http_strata_vars[type].len
                    && ngx_strncmp(p, ngx_http_strata_vars[type].data,
                                   ngx_http_strata_vars[type].len)
                       == 0)
                {
                    break;
                }
            }

            if (type > NGX_HTTP_STRATA_PAGE_CONTACT) {
                type = NGX_HTTP_STRATA_PAGE_TEXT;
            }
        }

        if (type == NGX_HTTP_STRATA_PAGE_TEXT) {
            p++;
            continue;
        }

        /* flush the text before the placeholder, then the placeholder */

        if (p > start) {
            part = ngx_array_push(&page->parts);
            if (part == NULL) {
                return NULL;
            }

            part->type = NGX_HTTP_STRATA_PAGE_TEXT;
            part->text.data = start;
            part->text.len = p - start;
            page->text_len += part->text.len;
        }

        part = ngx_array_push(&page->parts);
        if (part == NULL) {
            return NULL;
        }

        part->type = type;
        ngx_str_null(&part->text);
        page->nvars++;

        p += ngx_http_strata_vars[type].len;
        start = p;
    }

    if (p > start) {
        part = ngx_array_push(&page->parts);
        if (part == NULL) {
            return NULL;
        }

        part->type = NGX_HTTP_STRATA_PAGE_TEXT;
        part->text.data = start;
        part->text.len = p - start;
        page->text_len += part->text.len;
    }

    return page;
}
