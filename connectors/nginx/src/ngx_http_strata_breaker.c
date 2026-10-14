/*
 * Worker circuit breaker (W11-N-01, nginx-module.md › Circuit breaker cấp
 * worker).
 *
 * Each worker watches the internal errors of its own engine calls and,
 * past a threshold, runs requests in degraded mode (STRATA_TXF_DEGRADED:
 * protocol layer and ip_match rules only) for a while, then lets a sample
 * of requests through the full engine again:
 *
 *   Closed     full engine; Open when errors > threshold within a window
 *              with at least min requests
 *   Open       degraded for open_time, doubled on each reopen, up to 5 min
 *   Half-open  1 request in 20 through the full engine for one window;
 *              errors < 0.5% of them: Closed, else Open again
 *
 * Only internal errors count (panic, invalid state or argument, a NULL
 * transaction). STRATA_E_BUDGET does not: heavy requests must not be able
 * to switch the WAF to degraded mode. Neither do STRATA_E_BUNDLE (no
 * bundle, handled by the fail mode) and STRATA_E_INCOMPLETE (the connector
 * could not pass the body). Requests run in degraded mode are not counted.
 *
 * State is per worker, in plain static variables: no lock, no I/O.
 */

#include "ngx_http_strata_module.h"


#define NGX_HTTP_STRATA_BREAKER_OPEN_MAX   ((ngx_msec_t) 5 * 60 * 1000)
#define NGX_HTTP_STRATA_BREAKER_SAMPLE     20      /* 5% in half-open */
#define NGX_HTTP_STRATA_BREAKER_CLOSE_BP   50      /* 0.5% */


typedef struct {
    ngx_uint_t      state;
    ngx_msec_t      since;          /* window or open period start */
    ngx_msec_t      open_for;       /* current open period */
    ngx_uint_t      requests;
    ngx_uint_t      errors;
    ngx_uint_t      seq;            /* half-open sampling */
} ngx_http_strata_breaker_t;


static ngx_http_strata_breaker_t  ngx_http_strata_br;


static void
ngx_http_strata_breaker_set(ngx_http_strata_main_conf_t *smcf,
    ngx_uint_t state, ngx_log_t *log)
{
    static const char  *names[] = { "closed", "open", "half-open" };

    ngx_uint_t  level;

    if (state == NGX_HTTP_STRATA_BREAKER_OPEN) {
        if (ngx_http_strata_br.state == NGX_HTTP_STRATA_BREAKER_HALF_OPEN) {
            ngx_http_strata_br.open_for = ngx_min(
                ngx_http_strata_br.open_for * 2,
                NGX_HTTP_STRATA_BREAKER_OPEN_MAX);

        } else {
            ngx_http_strata_br.open_for = smcf->breaker_open;
        }

        ngx_http_strata_metrics_breaker_open();
    }

    level = (state == NGX_HTTP_STRATA_BREAKER_CLOSED) ? NGX_LOG_NOTICE
                                                      : NGX_LOG_WARN;

    ngx_log_error(level, log, 0,
                  "strata: circuit breaker %s, %ui internal errors in %ui "
                  "requests%s",
                  names[state], ngx_http_strata_br.errors,
                  ngx_http_strata_br.requests,
                  state == NGX_HTTP_STRATA_BREAKER_OPEN
                  ? ", degraded mode" : "");

    ngx_http_strata_br.state = state;
    ngx_http_strata_br.since = ngx_current_msec;
    ngx_http_strata_br.requests = 0;
    ngx_http_strata_br.errors = 0;
    ngx_http_strata_br.seq = 0;

    ngx_http_strata_metrics_breaker_state(state);
}


/* errors / requests above a share in basis points */

static ngx_uint_t
ngx_http_strata_breaker_over(ngx_uint_t share)
{
    return ngx_http_strata_br.errors * 10000
           > share * ngx_http_strata_br.requests;
}


/* at the end of a half-open window: back to closed, or open again */

static void
ngx_http_strata_breaker_tick(ngx_http_strata_main_conf_t *smcf, ngx_log_t *log)
{
    ngx_msec_t  elapsed;

    elapsed = ngx_current_msec - ngx_http_strata_br.since;

    switch (ngx_http_strata_br.state) {

    case NGX_HTTP_STRATA_BREAKER_OPEN:
        if (elapsed >= ngx_http_strata_br.open_for) {
            ngx_http_strata_breaker_set(smcf,
                                        NGX_HTTP_STRATA_BREAKER_HALF_OPEN, log);
        }
        break;

    case NGX_HTTP_STRATA_BREAKER_HALF_OPEN:
        if (elapsed >= smcf->breaker_window) {
            ngx_http_strata_breaker_set(smcf,
                ngx_http_strata_breaker_over(NGX_HTTP_STRATA_BREAKER_CLOSE_BP)
                ? NGX_HTTP_STRATA_BREAKER_OPEN
                : NGX_HTTP_STRATA_BREAKER_CLOSED, log);
        }
        break;

    default: /* closed: a new window */
        if (elapsed >= smcf->breaker_window) {
            ngx_http_strata_br.since = ngx_current_msec;
            ngx_http_strata_br.requests = 0;
            ngx_http_strata_br.errors = 0;
        }
    }
}


/* whether the next request runs in degraded mode */

ngx_uint_t
ngx_http_strata_breaker_degraded(ngx_http_request_t *r)
{
    ngx_http_strata_main_conf_t  *smcf;

    smcf = ngx_http_get_module_main_conf(r, ngx_http_strata_module);

    if (!smcf->breaker) {
        return 0;
    }

    ngx_http_strata_breaker_tick(smcf, r->connection->log);

    switch (ngx_http_strata_br.state) {

    case NGX_HTTP_STRATA_BREAKER_OPEN:
        return 1;

    case NGX_HTTP_STRATA_BREAKER_HALF_OPEN:
        return ngx_http_strata_br.seq++ % NGX_HTTP_STRATA_BREAKER_SAMPLE != 0;

    default:
        return 0;
    }
}


/* once per request run through the full engine, with its verdict */

void
ngx_http_strata_breaker_record(ngx_http_request_t *r, strata_rc_t error)
{
    ngx_http_strata_main_conf_t  *smcf;

    smcf = ngx_http_get_module_main_conf(r, ngx_http_strata_module);

    if (!smcf->breaker
        || ngx_http_strata_br.state == NGX_HTTP_STRATA_BREAKER_OPEN)
    {
        return;
    }

    ngx_http_strata_breaker_tick(smcf, r->connection->log);

    ngx_http_strata_br.requests++;

    if (error == STRATA_E_INTERNAL || error == STRATA_E_INVALID
        || error == STRATA_E_STATE)
    {
        ngx_http_strata_br.errors++;
    }

    if (ngx_http_strata_br.state == NGX_HTTP_STRATA_BREAKER_CLOSED
        && ngx_http_strata_br.requests >= smcf->breaker_min
        && ngx_http_strata_breaker_over(smcf->breaker_share))
    {
        ngx_http_strata_breaker_set(smcf, NGX_HTTP_STRATA_BREAKER_OPEN,
                                    r->connection->log);
    }
}


void
ngx_http_strata_breaker_init_process(void)
{
    ngx_memzero(&ngx_http_strata_br, sizeof(ngx_http_strata_breaker_t));
    ngx_http_strata_br.since = ngx_current_msec;
    ngx_http_strata_metrics_breaker_state(NGX_HTTP_STRATA_BREAKER_CLOSED);
}


/* strata_breaker_threshold <share>% <window> <min requests> [open=<time>] */

char *
ngx_http_strata_breaker_threshold(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_strata_main_conf_t *smcf = conf;

    ngx_int_t   n;
    ngx_str_t  *value, s;
    ngx_msec_t  t;

    if (smcf->breaker_window != NGX_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    /* share: "2%" or "0.5%", two decimals at most, in basis points */

    s = value[1];
    if (s.len < 2 || s.data[s.len - 1] != '%') {
        goto invalid;
    }
    s.len--;

    n = ngx_atofp(s.data, s.len, 2);
    if (n <= 0 || n > 10000) {
        goto invalid;
    }
    smcf->breaker_share = (ngx_uint_t) n;

    t = ngx_parse_time(&value[2], 0);
    if (t == (ngx_msec_t) NGX_ERROR || t == 0) {
        goto invalid;
    }
    smcf->breaker_window = t;

    n = ngx_atoi(value[3].data, value[3].len);
    if (n <= 0) {
        goto invalid;
    }
    smcf->breaker_min = (ngx_uint_t) n;

    if (cf->args->nelts == 5) {
        s = value[4];
        if (s.len <= sizeof("open=") - 1
            || ngx_strncmp(s.data, "open=", sizeof("open=") - 1) != 0)
        {
            goto invalid;
        }
        s.data += sizeof("open=") - 1;
        s.len -= sizeof("open=") - 1;

        t = ngx_parse_time(&s, 0);
        if (t == (ngx_msec_t) NGX_ERROR || t == 0
            || t > NGX_HTTP_STRATA_BREAKER_OPEN_MAX)
        {
            goto invalid;
        }
        smcf->breaker_open = t;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid strata_breaker_threshold, expected "
                       "<share>%% <window> <min requests> [open=<time>]");
    return NGX_CONF_ERROR;
}
