/*
 * Events and metrics (W07-N-01).
 *
 * Metrics: the master creates the metrics file (docs/design/control-file.md,
 * "Metrics file") once the configuration is read; workers inherit the
 * mapping and each writes only its own slot, one 64-bit store per counter.
 * Without the file the module still inspects requests: it only logs it.
 *
 * Events: each worker sends what strata_tx_event() returns as one Unix
 * datagram (nginx-module.md, "Giao diện gửi sự kiện"), never blocking; a
 * full socket or a missing agent drops the event and counts it.
 */

#include "ngx_http_strata_module.h"

#include <sys/mman.h>
#include <sys/un.h>


#define ngx_http_strata_metric_add(i, v)                                      \
    do {                                                                      \
        if (ngx_http_strata_slot) {                                           \
            (void) __atomic_fetch_add(&ngx_http_strata_slot[i], (v),          \
                                      __ATOMIC_RELAXED);                      \
        }                                                                     \
    } while (0)

#define ngx_http_strata_metric_set(i, v)                                      \
    do {                                                                      \
        if (ngx_http_strata_slot) {                                           \
            __atomic_store_n(&ngx_http_strata_slot[i], (v), __ATOMIC_RELAXED); \
        }                                                                     \
    } while (0)


static void ngx_http_strata_metrics_canary(ngx_http_strata_ctx_t *ctx);


u_char                     ngx_http_strata_event_buf[NGX_HTTP_STRATA_EVENT_MAX];

/* per worker */
static volatile uint64_t  *ngx_http_strata_slot;
static ngx_socket_t        ngx_http_strata_sink = (ngx_socket_t) -1;
static struct sockaddr_un  ngx_http_strata_sink_addr;
/*
 * The socket is connect()ed to the agent's, so a send does not look the
 * path up again (docs/decisions/ring-buffer.md, #29). When the agent is
 * away the next connect is tried at most once a second.
 */
static ngx_flag_t          ngx_http_strata_sink_up;
static ngx_msec_t          ngx_http_strata_sink_retry;

#define NGX_HTTP_STRATA_SINK_RETRY  1000


static ngx_flag_t
ngx_http_strata_sink_connect(void)
{
    struct sockaddr  *sa = (struct sockaddr *) &ngx_http_strata_sink_addr;

    ngx_http_strata_sink_up = connect(ngx_http_strata_sink, sa,
                                      sizeof(ngx_http_strata_sink_addr))
                              == 0;
    if (!ngx_http_strata_sink_up) {
        ngx_http_strata_sink_retry = ngx_current_msec
                                     + NGX_HTTP_STRATA_SINK_RETRY;
    }

    return ngx_http_strata_sink_up;
}


static void
ngx_http_strata_metrics_unmap(void *data)
{
    ngx_http_strata_main_conf_t  *smcf = data;

    (void) munmap(smcf->metrics_base, smcf->metrics_len);
    smcf->metrics_base = NULL;
}


/* master, after the configuration is read: a temporary file, sized and
 * with its header, renamed over the previous one (the agent opens the file
 * again at each scrape; workers of an older cycle keep the old inode) */

void
ngx_http_strata_metrics_create(ngx_cycle_t *cycle,
    ngx_http_strata_main_conf_t *smcf)
{
    int                  fd;
    u_char               tmp[NGX_MAX_PATH];
    u_char               hdr[NGX_HTTP_STRATA_METRICS_HEADER];
    void                *p;
    uint32_t             v[4];
    uint64_t             now;
    ngx_core_conf_t     *ccf;
    ngx_pool_cleanup_t  *cln;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    smcf->metrics_slots = ngx_min(ngx_max(ccf->worker_processes, 1), 1024);
    smcf->metrics_len = NGX_HTTP_STRATA_METRICS_HEADER
                        + smcf->metrics_slots * NGX_HTTP_STRATA_METRICS_SLOT;

    if (smcf->metrics_file.len + sizeof(".tmp.") + NGX_INT64_LEN
        >= NGX_MAX_PATH)
    {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "strata: metrics file path \"%V\" is too long",
                      &smcf->metrics_file);
        return;
    }

    (void) ngx_sprintf(tmp, "%V.tmp.%P%Z", &smcf->metrics_file, ngx_pid);

    ngx_memzero(hdr, sizeof(hdr));
    ngx_memcpy(hdr, "STRMET1", sizeof("STRMET1"));
    v[0] = 1;
    v[1] = (uint32_t) smcf->metrics_slots;
    v[2] = NGX_HTTP_STRATA_METRICS_SLOT;
    v[3] = NGX_HTTP_STRATA_METRICS_COUNTERS;
    ngx_memcpy(hdr + 8, v, sizeof(v));
    now = (uint64_t) ngx_time() * 1000;
    ngx_memcpy(hdr + 24, &now, sizeof(now));
    ngx_memcpy(hdr + 32, NGINX_VERSION, ngx_min(sizeof(NGINX_VERSION) - 1, 15));
    ngx_memcpy(hdr + 48, NGX_HTTP_STRATA_VERSION, sizeof(NGX_HTTP_STRATA_VERSION) - 1);
    v[0] = STRATA_ABI_VERSION;
    ngx_memcpy(hdr + 60, v, sizeof(uint32_t));

    /*
     * The directory may be the agent's: a link planted at this name must
     * not make the master (root) truncate and map another file (audit
     * 22/10/2026). Remove the name, then create a new file only.
     */
    (void) unlink((char *) tmp);
    fd = open((char *) tmp, O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0644);
    if (fd == -1) {
        goto failed;
    }

    if (ftruncate(fd, (off_t) smcf->metrics_len) == -1
        || pwrite(fd, hdr, sizeof(hdr), 0) != (ssize_t) sizeof(hdr)
        || rename((char *) tmp, (char *) smcf->metrics_file.data) == -1)
    {
        (void) close(fd);
        (void) unlink((char *) tmp);
        goto failed;
    }

    p = mmap(NULL, smcf->metrics_len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    (void) close(fd);

    if (p == MAP_FAILED) {
        goto failed;
    }

    cln = ngx_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        (void) munmap(p, smcf->metrics_len);
        return;
    }

    smcf->metrics_base = p;
    cln->handler = ngx_http_strata_metrics_unmap;
    cln->data = smcf;

    return;

failed:

    ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                  "strata: metrics file \"%V\" not written, "
                  "workers run without it", &smcf->metrics_file);
}


void
ngx_http_strata_events_init_process(ngx_cycle_t *cycle,
    ngx_http_strata_main_conf_t *smcf)
{
    size_t  len;

    if (smcf->metrics_base && ngx_worker < smcf->metrics_slots) {
        ngx_http_strata_slot = (volatile uint64_t *)
            (smcf->metrics_base + NGX_HTTP_STRATA_METRICS_HEADER
             + ngx_worker * NGX_HTTP_STRATA_METRICS_SLOT);

        ngx_http_strata_metric_set(NGX_HTTP_STRATA_METRIC_PID,
                                   (uint64_t) ngx_pid);
        ngx_http_strata_metric_set(NGX_HTTP_STRATA_METRIC_BUNDLE,
                                   smcf->bundle ? smcf->bundle->version : 0);
    }

    /* "unix:<path>", checked by the directive */
    len = smcf->event_socket.len - (sizeof("unix:") - 1);

    if (len >= sizeof(ngx_http_strata_sink_addr.sun_path)) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "strata: event socket path \"%V\" is too long, "
                      "events are dropped", &smcf->event_socket);
        return;
    }

    ngx_http_strata_sink_addr.sun_family = AF_UNIX;
    ngx_memcpy(ngx_http_strata_sink_addr.sun_path,
               smcf->event_socket.data + sizeof("unix:") - 1, len);
    ngx_http_strata_sink_addr.sun_path[len] = '\0';

    ngx_http_strata_sink = ngx_socket(AF_UNIX, SOCK_DGRAM, 0);

    if (ngx_http_strata_sink == (ngx_socket_t) -1
        || ngx_nonblocking(ngx_http_strata_sink) == -1)
    {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_socket_errno,
                      "strata: event socket not opened, events are dropped");
        ngx_http_strata_events_exit_process();
        return;
    }

    if (!ngx_http_strata_sink_connect()) {
        /* the agent may start later: the first event tries again */
        ngx_log_error(NGX_LOG_INFO, cycle->log, ngx_socket_errno,
                      "strata: event socket \"%V\" not reachable yet",
                      &smcf->event_socket);
        ngx_http_strata_sink_retry = 0;
    }
}


void
ngx_http_strata_events_exit_process(void)
{
    if (ngx_http_strata_sink != (ngx_socket_t) -1) {
        (void) ngx_close_socket(ngx_http_strata_sink);
        ngx_http_strata_sink = (ngx_socket_t) -1;
    }

    ngx_http_strata_sink_up = 0;

    ngx_http_strata_metric_set(NGX_HTTP_STRATA_METRIC_PID, 0);
    ngx_http_strata_slot = NULL;
}


/* the event in ngx_http_strata_event_buf: sent, or dropped and counted */

static ngx_flag_t
ngx_http_strata_sink_send(size_t len)
{
    return send(ngx_http_strata_sink, ngx_http_strata_event_buf, len,
                MSG_DONTWAIT) == (ssize_t) len;
}


void
ngx_http_strata_event_send(size_t len)
{
    ngx_err_t  err;

    if (ngx_http_strata_sink == (ngx_socket_t) -1) {
        goto dropped;
    }

    if (!ngx_http_strata_sink_up
        && ((ngx_msec_int_t) (ngx_current_msec
                              - ngx_http_strata_sink_retry) < 0
            || !ngx_http_strata_sink_connect()))
    {
        goto dropped;
    }

    if (ngx_http_strata_sink_send(len)) {
        return;
    }

    err = ngx_socket_errno;

    /*
     * The agent restarted (its socket is a new one) or went away: connect
     * again once now, so the first event after a restart is not lost.
     * A full queue (EAGAIN) keeps the connection and drops the event.
     */
    if ((err == ECONNREFUSED || err == ENOTCONN || err == ENOENT)
        && ngx_http_strata_sink_connect()
        && ngx_http_strata_sink_send(len))
    {
        return;
    }

dropped:

    ngx_http_strata_metric_add(NGX_HTTP_STRATA_METRIC_DROPPED, 1);
}


void
ngx_http_strata_metrics_bundle(uint64_t version)
{
    ngx_http_strata_metric_set(NGX_HTTP_STRATA_METRIC_BUNDLE, version);
}


void
ngx_http_strata_metrics_breaker_state(ngx_uint_t state)
{
    ngx_http_strata_metric_set(NGX_HTTP_STRATA_METRIC_BREAKER, state);
}


void
ngx_http_strata_metrics_breaker_open(void)
{
    ngx_http_strata_metric_add(NGX_HTTP_STRATA_METRIC_BREAKER_OPENS, 1);
}


/* once per request, when its transaction ends */

void
ngx_http_strata_metrics_record(ngx_http_strata_ctx_t *ctx, uint64_t engine_us)
{
    static const uint64_t  bounds[] = {
        50, 100, 200, 500, 1000, 2000, 5000, 10000
    };

    ngx_uint_t  b;

    if (ctx->verdict.action <= STRATA_ACTION_BLOCK) {
        ngx_http_strata_metric_add(NGX_HTTP_STRATA_METRIC_ALLOW
                                   + ctx->verdict.action, 1);
    }

    ngx_http_strata_metric_add(NGX_HTTP_STRATA_METRIC_BODY,
                               (uint64_t) ctx->body_inspected);

    if (ctx->degraded) {
        ngx_http_strata_metric_add(NGX_HTTP_STRATA_METRIC_DEGRADED, 1);
    }

    if (ctx->failed) {
        ngx_http_strata_metric_add(ctx->fail_closed
                                   ? NGX_HTTP_STRATA_METRIC_FAIL_CLOSED
                                   : NGX_HTTP_STRATA_METRIC_FAIL_OPEN, 1);
    }

    if (ctx->verdict.error == STRATA_E_BUDGET) {
        ngx_http_strata_metric_add(NGX_HTTP_STRATA_METRIC_BUDGET, 1);
    }

    ngx_http_strata_metric_add(NGX_HTTP_STRATA_METRIC_ENGINE_NS,
                               engine_us * 1000);

    for (b = 0; b < sizeof(bounds) / sizeof(bounds[0]); b++) {
        if (engine_us <= bounds[b]) {
            break;
        }
    }

    ngx_http_strata_metric_add(NGX_HTTP_STRATA_METRIC_HISTOGRAM + b, 1);

    ngx_http_strata_metrics_canary(ctx);
}


/*
 * W12-G2-01: a request of a policy with an enforce canary counts in its
 * group, so the control plane can compare the two sides. Runs from the pool
 * cleanup: r and its upstream states are still in the pool.
 */

static void
ngx_http_strata_metrics_canary(ngx_http_strata_ctx_t *ctx)
{
    static const ngx_msec_int_t  bounds[] = {
        5, 10, 25, 50, 100, 250, 500, 1000
    };

    ngx_uint_t                  i, b;
    ngx_time_t                 *tp;
    ngx_msec_int_t              ms;
    ngx_http_request_t         *r = ctx->r;
    ngx_http_upstream_state_t  *us;

    if (ctx->verdict.flags & STRATA_VF_CANARY) {
        i = NGX_HTTP_STRATA_METRIC_CANARY;

    } else if (ctx->verdict.flags & STRATA_VF_CANARY_SHADOW) {
        i = NGX_HTTP_STRATA_METRIC_CANARY + NGX_HTTP_STRATA_METRIC_GROUP;

    } else {
        return;
    }

    ngx_http_strata_metric_add(i, 1);

    if (ctx->verdict.action == STRATA_ACTION_BLOCK) {
        ngx_http_strata_metric_add(i + 1, 1);

    } else if (ctx->verdict.action == STRATA_ACTION_LOG) {
        ngx_http_strata_metric_add(i + 2, 1);
    }

    if (r->upstream_states != NULL && r->upstream_states->nelts > 0) {
        us = r->upstream_states->elts;

        if (us[r->upstream_states->nelts - 1].status >= 500) {
            ngx_http_strata_metric_add(i + 3, 1);
        }
    }

    tp = ngx_timeofday();
    ms = (ngx_msec_int_t) ((tp->sec - r->start_sec) * 1000
                           + (tp->msec - r->start_msec));

    for (b = 0; b < sizeof(bounds) / sizeof(bounds[0]); b++) {
        if (ms <= bounds[b]) {
            break;
        }
    }

    ngx_http_strata_metric_add(i + 4 + b, 1);
}
