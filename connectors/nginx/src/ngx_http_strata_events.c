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


u_char                     ngx_http_strata_event_buf[NGX_HTTP_STRATA_EVENT_MAX];

/* per worker */
static volatile uint64_t  *ngx_http_strata_slot;
static ngx_socket_t        ngx_http_strata_sink = (ngx_socket_t) -1;
static struct sockaddr_un  ngx_http_strata_sink_addr;


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

    fd = open((char *) tmp, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0644);
    if (fd == -1) {
        goto failed;
    }

    if (ftruncate(fd, smcf->metrics_len) == -1
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
    }
}


void
ngx_http_strata_events_exit_process(void)
{
    if (ngx_http_strata_sink != (ngx_socket_t) -1) {
        (void) ngx_close_socket(ngx_http_strata_sink);
        ngx_http_strata_sink = (ngx_socket_t) -1;
    }

    ngx_http_strata_metric_set(NGX_HTTP_STRATA_METRIC_PID, 0);
    ngx_http_strata_slot = NULL;
}


/* the event in ngx_http_strata_event_buf: sent, or dropped and counted */

void
ngx_http_strata_event_send(size_t len)
{
    if (ngx_http_strata_sink == (ngx_socket_t) -1
        || sendto(ngx_http_strata_sink, ngx_http_strata_event_buf, len,
                  MSG_DONTWAIT,
                  (struct sockaddr *) &ngx_http_strata_sink_addr,
                  sizeof(ngx_http_strata_sink_addr)) != (ssize_t) len)
    {
        ngx_http_strata_metric_add(NGX_HTTP_STRATA_METRIC_DROPPED, 1);
    }
}


void
ngx_http_strata_metrics_bundle(uint64_t version)
{
    ngx_http_strata_metric_set(NGX_HTTP_STRATA_METRIC_BUNDLE, version);
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
}
