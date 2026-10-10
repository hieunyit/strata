/*
 * $strata_* variables. Values come from the main request's context, which
 * survives internal redirects, so they also work in access_log.
 */

#include "ngx_http_strata_module.h"


static ngx_int_t ngx_http_strata_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


#define NGX_HTTP_STRATA_VAR_BLOCK_ID  0
#define NGX_HTTP_STRATA_VAR_ACTION    1
#define NGX_HTTP_STRATA_VAR_SCORE     2
#define NGX_HTTP_STRATA_VAR_RULES     3
#define NGX_HTTP_STRATA_VAR_POLICY    4
#define NGX_HTTP_STRATA_VAR_BUNDLE    5
#define NGX_HTTP_STRATA_VAR_TIME_US   6


static ngx_http_variable_t  ngx_http_strata_variables[] = {

    { ngx_string("strata_block_id"), NULL, ngx_http_strata_variable,
      NGX_HTTP_STRATA_VAR_BLOCK_ID, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("strata_action"), NULL, ngx_http_strata_variable,
      NGX_HTTP_STRATA_VAR_ACTION, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("strata_score"), NULL, ngx_http_strata_variable,
      NGX_HTTP_STRATA_VAR_SCORE, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("strata_rules"), NULL, ngx_http_strata_variable,
      NGX_HTTP_STRATA_VAR_RULES, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("strata_policy"), NULL, ngx_http_strata_variable,
      NGX_HTTP_STRATA_VAR_POLICY, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("strata_bundle_version"), NULL, ngx_http_strata_variable,
      NGX_HTTP_STRATA_VAR_BUNDLE, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("strata_time_us"), NULL, ngx_http_strata_variable,
      NGX_HTTP_STRATA_VAR_TIME_US, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_str_t  ngx_http_strata_actions[] = {
    ngx_string("allow"),
    ngx_string("log"),
    ngx_string("challenge"),
    ngx_string("block"),
    ngx_string("error"),
};


ngx_int_t
ngx_http_strata_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_strata_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_strata_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    u_char                 *p, *last;
    ngx_uint_t              i, n, action;
    ngx_http_strata_ctx_t  *ctx;

    ctx = ngx_http_strata_get_ctx(r);

    if (ctx == NULL || !ctx->decided) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->stream && ctx->tx) {
        /*
         * "stream" decides before the body (shadow only, never blocks):
         * pick up what the body filter found since, e.g. for access_log.
         */
        strata_tx_verdict(ctx->tx, &ctx->verdict);
        ctx->verdict.block_id[STRATA_BLOCK_ID_SIZE - 1] = '\0';
        ctx->failed = (ctx->verdict.error != STRATA_OK);
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    switch (data) {

    case NGX_HTTP_STRATA_VAR_BLOCK_ID:
        v->data = (u_char *) ctx->verdict.block_id;
        v->len = ngx_strlen(v->data);
        break;

    case NGX_HTTP_STRATA_VAR_ACTION:
        action = ctx->failed ? NGX_HTTP_STRATA_ACTION_ERROR
                             : ctx->verdict.action;

        if (action > NGX_HTTP_STRATA_ACTION_ERROR) {
            action = NGX_HTTP_STRATA_ACTION_ERROR;
        }

        v->data = ngx_http_strata_actions[action].data;
        v->len = ngx_http_strata_actions[action].len;
        break;

    case NGX_HTTP_STRATA_VAR_SCORE:
        p = ngx_pnalloc(r->pool, NGX_INT32_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->data = p;
        v->len = ngx_slprintf(p, p + NGX_INT32_LEN, "%D",
                              ctx->verdict.score) - p;
        break;

    case NGX_HTTP_STRATA_VAR_RULES:
        n = ngx_min(ctx->verdict.n_rules, STRATA_MAX_RULES);

        p = ngx_pnalloc(r->pool, n * (NGX_INT32_LEN + 1) + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->data = p;
        last = p + n * (NGX_INT32_LEN + 1) + 1;

        for (i = 0; i < n; i++) {
            if (i) {
                *p++ = ',';
            }

            p = ngx_slprintf(p, last, "%uD", ctx->verdict.rules[i]);
        }

        v->len = p - v->data;
        break;

    case NGX_HTTP_STRATA_VAR_BUNDLE:
        if (ctx->bundle_version == 0) {
            v->len = 0;
            v->data = (u_char *) "";
            break;
        }

        p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->data = p;
        v->len = ngx_slprintf(p, p + NGX_INT64_LEN, "%uL",
                              ctx->bundle_version) - p;
        break;

    case NGX_HTTP_STRATA_VAR_TIME_US:
        p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->data = p;
        v->len = ngx_slprintf(p, p + NGX_INT64_LEN, "%uL",
                              (uint64_t) strata_tx_time_us(ctx->tx)) - p;
        break;

    default: /* NGX_HTTP_STRATA_VAR_POLICY */
        v->data = ctx->policy.data;
        v->len = ctx->policy.len;
        break;
    }

    return NGX_OK;
}
