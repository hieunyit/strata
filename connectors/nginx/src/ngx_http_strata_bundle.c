/*
 * Bundle loading and hot reload (docs/design/control-file.md).
 *
 * Master: while reading the configuration, reads the control file and maps
 * the current bundle read-only and shared; workers inherit the mapping.
 *
 * Worker: maps the control file once, then a timer reads its generation from
 * memory only. A new generation posts a load task to the "default" thread
 * pool (open, mmap, signature check in strata_engine_map, version check);
 * the completion handler swaps the current bundle in the event loop. A bundle
 * is unmapped, again in the thread pool, when its last reference is released.
 */

#include "ngx_http_strata_module.h"

#include <sys/mman.h>


typedef void (*ngx_http_strata_done_pt)(void *ctx);


typedef struct {
    /* in */
    u_char                       path[NGX_MAX_PATH];
    u_char                       name[NGX_HTTP_STRATA_CTL_NAME_MAX + 1];
    size_t                       name_len;
    u_char                       key[STRATA_PUBKEY_LEN];
    uint64_t                     generation;
    uint64_t                     current_version;
    unsigned                     have_current:1;
    unsigned                     open_ctl:1;

    /* out */
    strata_engine_t             *engine;
    u_char                      *base;
    size_t                       len;
    strata_engine_info_t         info;
    ngx_err_t                    err;
    const char                  *step;          /* failed syscall, or NULL */
    strata_err_t                 serr;          /* strata_engine_map error */
    unsigned                     stale:1;       /* not newer, no rollback */
} ngx_http_strata_load_t;


#if (NGX_THREADS)
typedef struct {
    ngx_thread_task_t            task;
    ngx_http_strata_done_pt      done;
} ngx_http_strata_task_t;
#endif


static ngx_int_t ngx_http_strata_read_pubkey(ngx_conf_t *cf, ngx_str_t *path,
    u_char *key);
static ngx_int_t ngx_http_strata_ctl_read(const u_char *ctl, uint64_t *gen,
    ngx_str_t *name);
static ngx_int_t ngx_http_strata_bundle_path(ngx_str_t *dir, ngx_str_t *name,
    u_char *path);
static void ngx_http_strata_load_handler(void *data, ngx_log_t *log);
static void ngx_http_strata_load_done(void *data);
static void ngx_http_strata_unmap_handler(void *data, ngx_log_t *log);
static void ngx_http_strata_unmap_done(void *data);
static void ngx_http_strata_post(void (*handler)(void *data, ngx_log_t *log),
    ngx_http_strata_done_pt done, void *ctx);
static void ngx_http_strata_tick(ngx_event_t *ev);
static void ngx_http_strata_schedule(void);
static void ngx_http_strata_bundle_cleanup(void *data);
static ngx_int_t ngx_http_strata_bundle_page(ngx_http_strata_bundle_t *bundle,
    ngx_pool_t *pool);


typedef struct {
    uint32_t  flags;
    uint32_t  num_policies;
    u_char    policies[32][56];
} ngx_http_strata_force_shadow_t;

static ngx_http_strata_force_shadow_t  ngx_http_strata_force_shadow;
static ngx_uint_t                      ngx_http_strata_fs_warned = 0;
static u_char                          ngx_http_strata_current_name[NGX_HTTP_STRATA_CTL_NAME_MAX + 1];
static size_t                          ngx_http_strata_current_name_len = 0;

/* per worker */
static ngx_http_strata_main_conf_t  *ngx_http_strata_smcf;
static ngx_http_strata_bundle_t     *ngx_http_strata_current;
static u_char                       *ngx_http_strata_ctl;
static uint64_t                      ngx_http_strata_seen;
static ngx_uint_t                    ngx_http_strata_busy;
static ngx_uint_t                    ngx_http_strata_ctl_invalid;
static ngx_event_t                   ngx_http_strata_timer;
static ngx_connection_t              ngx_http_strata_dummy;  /* ev->data, for
                                                               debug logging */


/* master, at configuration time */

ngx_int_t
ngx_http_strata_bundle_init(ngx_conf_t *cf, ngx_http_strata_main_conf_t *smcf)
{
    uint64_t                   gen;
    ngx_int_t                  rc;
    ngx_str_t                  name;
    ngx_pool_cleanup_t        *cln;
    ngx_http_strata_load_t    *ld;
    ngx_http_strata_bundle_t  *bundle;
    u_char                     path[NGX_MAX_PATH];

    if (smcf->pubkey_file.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"strata_bundle_pubkey\" is required when "
                           "\"strata\" is enabled");
        return NGX_ERROR;
    }

    if (ngx_conf_full_name(cf->cycle, &smcf->pubkey_file, 1) != NGX_OK
        || ngx_conf_full_name(cf->cycle, &smcf->bundle_dir, 1) != NGX_OK
        || ngx_conf_full_name(cf->cycle, &smcf->control_file, 1) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_strata_read_pubkey(cf, &smcf->pubkey_file, smcf->pubkey)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#if (NGX_THREADS)
    smcf->thread_pool = ngx_thread_pool_add(cf, NULL);
    if (smcf->thread_pool == NULL) {
        return NGX_ERROR;
    }
#endif

    /* the control file names the current bundle */

    ld = ngx_pcalloc(cf->pool, sizeof(ngx_http_strata_load_t));
    if (ld == NULL || smcf->control_file.len + 1 > NGX_MAX_PATH) {
        return NGX_ERROR;
    }

    ngx_memcpy(ld->path, smcf->control_file.data, smcf->control_file.len + 1);
    ld->open_ctl = 1;

    ngx_http_strata_load_handler(ld, cf->log);

    if (ld->step) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, ld->err,
                           "strata: no control file \"%V\", requests follow "
                           "strata_fail_mode until a bundle is published",
                           &smcf->control_file);
        return NGX_OK;
    }

    rc = ngx_http_strata_ctl_read(ld->base, &gen, &name);

    if (rc == NGX_OK) {
        /* copy the name out before unmapping */
        ngx_memcpy(ngx_http_strata_current_name, name.data, name.len);
        ngx_http_strata_current_name[name.len] = '\0';
        ngx_http_strata_current_name_len = name.len;
        rc = ngx_http_strata_bundle_path(&smcf->bundle_dir, &name, path);
    }

    munmap(ld->base, NGX_HTTP_STRATA_CTL_SIZE);

    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "strata: control file \"%V\" is %s, requests "
                           "follow strata_fail_mode until it is valid",
                           &smcf->control_file,
                           rc == NGX_AGAIN ? "being written" : "invalid");
        return NGX_OK;
    }

    ngx_memzero(ld, sizeof(ngx_http_strata_load_t));
    ngx_memcpy(ld->path, path, NGX_MAX_PATH);
    ngx_memcpy(ld->key, smcf->pubkey, STRATA_PUBKEY_LEN);

    ngx_http_strata_load_handler(ld, cf->log);

    if (ld->step) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, ld->err,
                           "strata: %s(\"%s\") failed, requests follow "
                           "strata_fail_mode", ld->step, ld->path);
        return NGX_OK;
    }

    if (ld->engine == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "strata: bundle \"%s\" rejected (%D): %s",
                           ld->path, ld->serr.code, ld->serr.msg);
        return NGX_ERROR;
    }

    bundle = ngx_pcalloc(cf->pool, sizeof(ngx_http_strata_bundle_t));
    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (bundle == NULL || cln == NULL) {
        strata_engine_release(ld->engine);
        munmap(ld->base, ld->len);
        return NGX_ERROR;
    }

    bundle->engine = ld->engine;
    bundle->base = ld->base;
    bundle->len = ld->len;
    bundle->version = ld->info.version;
    bundle->refs = 1;

    cln->handler = ngx_http_strata_bundle_cleanup;
    cln->data = bundle;

    smcf->bundle = bundle;
    smcf->generation = gen;

    if (ngx_http_strata_bundle_page(bundle, cf->pool) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_strata_check_stream(cf->log, NGX_LOG_EMERG, smcf,
                                     bundle->engine))
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * "strata_request_body_mode stream" only runs in shadow: a location using it
 * with a policy the bundle signs as enforce is a configuration error at
 * start-up, and a warning after a hot reload (the location stays in shadow).
 * Returns the number of such locations.
 */

ngx_uint_t
ngx_http_strata_check_stream(ngx_log_t *log, ngx_uint_t level,
    ngx_http_strata_main_conf_t *smcf, strata_engine_t *engine)
{
    ngx_uint_t                     i, n;
    strata_policy_info_t           info;
    ngx_http_strata_stream_loc_t  *sl;

    if (smcf->stream_locs == NULL) {
        return 0;
    }

    n = 0;
    sl = smcf->stream_locs->elts;

    for (i = 0; i < smcf->stream_locs->nelts; i++) {
        if (strata_engine_policy(engine,
                                 (strata_str_t) { sl[i].policy.data,
                                                  sl[i].policy.len },
                                 &info)
            != STRATA_OK
            || info.mode != STRATA_POLICY_ENFORCE)
        {
            continue;
        }

        ngx_log_error(level, log, 0,
                      "strata: location \"%V\" uses "
                      "\"strata_request_body_mode stream\", which only runs "
                      "in shadow, but its policy \"%V\" enforces%s",
                      &sl[i].location, &sl[i].policy,
                      level == NGX_LOG_EMERG ? "" : "; the location stays in "
                                                    "shadow");
        n++;
    }

    return n;
}


static void
ngx_http_strata_bundle_cleanup(void *data)
{
    ngx_http_strata_bundle_t  *bundle = data;

    /*
     * Configuration cycle destroyed (master on reload, or worker exit).
     * A worker may already have unmapped this bundle after a swap.
     */

    if (!bundle->unmapped) {
        bundle->unmapped = 1;
        strata_engine_release(bundle->engine);
        munmap(bundle->base, bundle->len);
    }
}


static ngx_int_t
ngx_http_strata_read_pubkey(ngx_conf_t *cf, ngx_str_t *path, u_char *key)
{
    ssize_t          n;
    ngx_fd_t         fd;
    ngx_int_t        rc;
    ngx_file_t       file;
    ngx_file_info_t  fi;

    fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", path);
        return NGX_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name = *path;
    file.log = cf->log;

    rc = NGX_ERROR;

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR
        || ngx_file_size(&fi) != STRATA_PUBKEY_LEN)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "strata: public key \"%V\" must be %d raw bytes",
                           path, STRATA_PUBKEY_LEN);
        goto done;
    }

    n = ngx_read_file(&file, key, STRATA_PUBKEY_LEN, 0);
    if (n != STRATA_PUBKEY_LEN) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "strata: short read of public key \"%V\"", path);
        goto done;
    }

    rc = NGX_OK;

done:

    ngx_close_file(fd);
    return rc;
}


/*
 * Seqlock reader. NGX_OK: stable and valid, "name" points into "ctl" and is
 * only valid until the next check; NGX_AGAIN: being written; NGX_ERROR:
 * invalid. Fields are little-endian, like every supported platform.
 */

static ngx_int_t
ngx_http_strata_ctl_read(const u_char *ctl, uint64_t *gen, ngx_str_t *name)
{
    u_char                          c;
    size_t                          i, j;
    uint16_t                        len;
    uint32_t                        layout;
    uint64_t                        g1, g2;
    u_char                          magic[8];
    uint32_t                        raw_flags, raw_npol;
    u_char                          raw_pols[32][56];
    ngx_uint_t                      valid;
    ngx_http_strata_force_shadow_t  fs;

    g1 = *(volatile const uint64_t *) (ctl + 16);
    if (g1 & 1) {
        return NGX_AGAIN;
    }

    ngx_memory_barrier();

    ngx_memcpy(magic, ctl, 8);
    ngx_memcpy(&layout, ctl + 8, 4);
    ngx_memcpy(&len, ctl + 64, 2);
    ngx_memcpy(&raw_flags, ctl + 324, 4);
    ngx_memcpy(&raw_npol, ctl + 328, 4);
    if (raw_npol <= 32) {
        ngx_memcpy(raw_pols, ctl + 336, raw_npol * 56);
    }

    ngx_memory_barrier();

    g2 = *(volatile const uint64_t *) (ctl + 16);
    if (g1 != g2) {
        return NGX_AGAIN;
    }

    if (ngx_memcmp(magic, "STRCTL1\0", 8) != 0
        || layout != 1
        || len == 0
        || len > NGX_HTTP_STRATA_CTL_NAME_MAX)
    {
        return NGX_ERROR;
    }

    name->data = (u_char *) ctl + 66;
    name->len = len;

    for (i = 0; i < len; i++) {
        c = name->data[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
        {
            return NGX_ERROR;
        }
    }

    if ((len == 1 && name->data[0] == '.')
        || (len == 2 && name->data[0] == '.' && name->data[1] == '.'))
    {
        return NGX_ERROR;
    }

    /* Validate force-shadow (untrusted input) */
    ngx_memzero(&fs, sizeof(ngx_http_strata_force_shadow_t));
    fs.flags = raw_flags;
    valid = (raw_npol <= 32);

    for (i = 0; i < raw_npol && valid; i++) {
        u_char *p = raw_pols[i];
        u_char *nul = memchr(p, '\0', 56);
        if (nul == NULL || nul == p) {
            valid = 0;
            break;
        }
        for (j = 0; p + j < nul; j++) {
            c = p[j];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                  || c == '.' || c == '_' || c == '-'))
            {
                valid = 0;
                break;
            }
        }
        if (valid) {
            ngx_memcpy(fs.policies[i], p, nul - p + 1);
        }
    }

    if (!valid && !ngx_http_strata_fs_warned) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "strata: invalid force_shadow in control file");
        ngx_http_strata_fs_warned = 1;
    }

    fs.num_policies = valid ? raw_npol : 0;

    ngx_http_strata_force_shadow = fs;
    *gen = g1;

    return NGX_OK;
}


ngx_uint_t
ngx_http_strata_is_force_shadow(ngx_str_t *policy)
{
    ngx_uint_t  i;

    if (ngx_http_strata_force_shadow.flags & 1) {
        return 1;
    }

    if (policy == NULL || policy->len == 0 || policy->len > 55) {
        return 0;
    }

    for (i = 0; i < ngx_http_strata_force_shadow.num_policies; i++) {
        if (ngx_strncmp(policy->data, ngx_http_strata_force_shadow.policies[i], policy->len) == 0
            && ngx_http_strata_force_shadow.policies[i][policy->len] == '\0')
        {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_http_strata_bundle_path(ngx_str_t *dir, ngx_str_t *name, u_char *path)
{
    u_char  *p;

    if (dir->len + 1 + name->len + 1 > NGX_MAX_PATH) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(path, dir->data, dir->len);
    *p++ = '/';
    p = ngx_cpymem(p, name->data, name->len);
    *p = '\0';

    return NGX_OK;
}


/* runs in a thread pool thread (or synchronously): no NGINX state touched */

static void
ngx_http_strata_load_handler(void *data, ngx_log_t *log)
{
    ngx_http_strata_load_t  *ld = data;
    int          fd;
    void        *p;
    struct stat  st;
    size_t       exp_len;

    (void) log;

    fd = open((char *) ld->path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        ld->err = ngx_errno;
        ld->step = "open";
        return;
    }

    if (fstat(fd, &st) == -1) {
        ld->err = ngx_errno;
        ld->step = "fstat";
        close(fd);
        return;
    }

    exp_len = ld->open_ctl ? NGX_HTTP_STRATA_CTL_SIZE : (size_t) st.st_size;
    if (st.st_size <= 0 || (size_t) st.st_size != exp_len) {
        ld->err = 0;
        ld->step = "size";
        close(fd);
        return;
    }

    ld->len = exp_len;
    p = mmap(NULL, ld->len, PROT_READ, MAP_SHARED, fd, 0);
    ld->err = ngx_errno;
    close(fd);

    if (p == MAP_FAILED) {
        ld->step = "mmap";
        return;
    }

    ld->base = p;

    if (ld->open_ctl) {
        return;
    }

    (void) madvise(p, ld->len, MADV_WILLNEED);

    /* signature and layout are verified here, off the event loop */
    ld->engine = strata_engine_map(ld->base, ld->len, ld->key, &ld->serr);
    ld->serr.msg[STRATA_ERR_MSG_SIZE - 1] = '\0';

    if (ld->engine == NULL) {
        munmap(ld->base, ld->len);
        ld->base = NULL;
        return;
    }

    strata_engine_info(ld->engine, &ld->info);

    if (ld->have_current
        && ld->info.version <= ld->current_version
        && !(ld->info.flags & STRATA_BUNDLE_ROLLBACK))
    {
        ld->stale = 1;
        strata_engine_release(ld->engine);
        ld->engine = NULL;
        munmap(ld->base, ld->len);
        ld->base = NULL;
    }
}


/* worker */

ngx_int_t
ngx_http_strata_bundle_init_process(ngx_cycle_t *cycle)
{
    ngx_http_strata_load_t       *ld;
    ngx_http_strata_main_conf_t  *smcf;

    smcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_strata_module);
    if (smcf == NULL || !smcf->enabled) {
        return NGX_OK;
    }

    ngx_http_strata_smcf = smcf;
    ngx_http_strata_current = smcf->bundle;   /* holds its "current" ref */
    ngx_http_strata_seen = smcf->generation;

    /* one-time syscalls at worker start, not on the request path */

    ld = ngx_calloc(sizeof(ngx_http_strata_load_t), cycle->log);
    if (ld == NULL || smcf->control_file.len + 1 > NGX_MAX_PATH) {
        ngx_free(ld);
        return NGX_ERROR;
    }

    ngx_memcpy(ld->path, smcf->control_file.data, smcf->control_file.len + 1);
    ld->open_ctl = 1;

    ngx_http_strata_load_handler(ld, cycle->log);
    ngx_http_strata_ctl = ld->base;      /* NULL: retried by the timer */
    ngx_free(ld);

    if (ngx_http_strata_ctl) {
        uint64_t   dummy_gen;
        ngx_str_t  dummy_name;
        (void) ngx_http_strata_ctl_read(ngx_http_strata_ctl, &dummy_gen,
                                        &dummy_name);
    }

#if !(NGX_THREADS)
    ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                  "strata: NGINX built without threads, bundles are loaded "
                  "in the event loop");
#endif

    ngx_http_strata_dummy.fd = (ngx_socket_t) -1;
    ngx_http_strata_timer.handler = ngx_http_strata_tick;
    ngx_http_strata_timer.log = cycle->log;
    ngx_http_strata_timer.data = &ngx_http_strata_dummy;
    ngx_http_strata_timer.cancelable = 1;

    ngx_http_strata_schedule();

    return NGX_OK;
}


void
ngx_http_strata_bundle_exit_process(ngx_cycle_t *cycle)
{
    if (ngx_http_strata_ctl) {
        munmap(ngx_http_strata_ctl, NGX_HTTP_STRATA_CTL_SIZE);
        ngx_http_strata_ctl = NULL;
    }
}


static void
ngx_http_strata_schedule(void)
{
    ngx_msec_t  t;

    t = ngx_http_strata_smcf->bundle_check;
    t += (ngx_msec_t) ngx_random() % (t / 4 + 1);   /* spread the workers */

    ngx_add_timer(&ngx_http_strata_timer, t);
}


static void
ngx_http_strata_tick(ngx_event_t *ev)
{
    uint64_t                     gen;
    ngx_int_t                    rc;
    ngx_str_t                    name;
    ngx_http_strata_load_t      *ld;
    ngx_http_strata_main_conf_t *smcf;

    if (ngx_exiting || ngx_quit || ngx_terminate) {
        return;
    }

    smcf = ngx_http_strata_smcf;

    if (ngx_http_strata_busy) {
        goto next;
    }

    if (ngx_http_strata_ctl == NULL) {
        /* control file missing at start: try again, off the event loop */

        ld = ngx_calloc(sizeof(ngx_http_strata_load_t), ev->log);
        if (ld == NULL) {
            goto next;
        }

        if (smcf->control_file.len + 1 > NGX_MAX_PATH) {
            ngx_free(ld);
            goto next;
        }

        ngx_memcpy(ld->path, smcf->control_file.data,
                   smcf->control_file.len + 1);
        ld->open_ctl = 1;

        ngx_http_strata_busy = 1;
        ngx_http_strata_post(ngx_http_strata_load_handler,
                             ngx_http_strata_load_done, ld);
        goto next;
    }

    /* the steady state: memory reads only */

    rc = ngx_http_strata_ctl_read(ngx_http_strata_ctl, &gen, &name);

    if (rc == NGX_ERROR) {
        if (!ngx_http_strata_ctl_invalid) {
            ngx_http_strata_ctl_invalid = 1;
            ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                          "strata: invalid control file \"%V\", keeping the "
                          "current bundle", &smcf->control_file);
        }
        goto next;
    }

    ngx_http_strata_ctl_invalid = 0;

    if (rc == NGX_AGAIN || gen == ngx_http_strata_seen) {
        goto next;
    }

    if (ngx_http_strata_current != NULL
        && name.len == ngx_http_strata_current_name_len
        && ngx_memcmp(name.data, ngx_http_strata_current_name, name.len) == 0)
    {
        /* generation changed only for force-shadow: flags already updated in memory */
        ngx_http_strata_seen = gen;
        goto next;
    }

    ld = ngx_calloc(sizeof(ngx_http_strata_load_t), ev->log);
    if (ld == NULL) {
        goto next;
    }

    if (ngx_http_strata_bundle_path(&smcf->bundle_dir, &name, ld->path)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                      "strata: bundle path too long");
        ngx_http_strata_seen = gen;
        ngx_free(ld);
        goto next;
    }

    ngx_memcpy(ld->name, name.data, name.len);
    ld->name[name.len] = '\0';
    ld->name_len = name.len;
    ngx_memcpy(ld->key, smcf->pubkey, STRATA_PUBKEY_LEN);
    ld->generation = gen;

    if (ngx_http_strata_current) {
        ld->have_current = 1;
        ld->current_version = ngx_http_strata_current->version;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "strata: generation %uL, loading \"%s\"", gen, ld->path);

    ngx_http_strata_busy = 1;
    ngx_http_strata_post(ngx_http_strata_load_handler,
                         ngx_http_strata_load_done, ld);

next:

    ngx_http_strata_schedule();
}


/* event loop: swap in the new bundle or report why it was refused */

static void
ngx_http_strata_load_done(void *data)
{
    ngx_http_strata_load_t  *ld = data;

    ngx_log_t                 *log;
    ngx_http_strata_bundle_t  *bundle, *old;

    log = ngx_cycle->log;
    ngx_http_strata_busy = 0;

    if (ld->open_ctl) {
        if (ld->base) {
            ngx_http_strata_ctl = ld->base;
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "strata: control file \"%s\" mapped", ld->path);
        }
        goto done;
    }

    /* do not retry the same generation, whatever the outcome */

    ngx_http_strata_seen = ld->generation;

    if (ld->step) {
        ngx_log_error(NGX_LOG_ERR, log, ld->err,
                      "strata: %s(\"%s\") failed, keeping the current bundle",
                      ld->step, ld->path);
        goto done;
    }

    if (ld->stale) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "strata: bundle \"%s\" version %uL is not newer than "
                      "%uL and not a signed rollback, keeping the current "
                      "bundle", ld->path, ld->info.version,
                      ld->current_version);
        goto done;
    }

    if (ld->engine == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "strata: bundle \"%s\" rejected (%D): %s, keeping the "
                      "current bundle", ld->path, ld->serr.code,
                      ld->serr.msg);
        goto done;
    }

    bundle = ngx_calloc(sizeof(ngx_http_strata_bundle_t), log);
    if (bundle == NULL) {
        strata_engine_release(ld->engine);
        munmap(ld->base, ld->len);
        goto done;
    }

    bundle->engine = ld->engine;
    bundle->base = ld->base;
    bundle->len = ld->len;
    bundle->version = ld->info.version;
    bundle->refs = 1;
    bundle->heap = 1;

    /* the template's parts point into the mapping: they live as long */

    bundle->pool = ngx_create_pool(1024, log);
    if (bundle->pool == NULL
        || ngx_http_strata_bundle_page(bundle, bundle->pool) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "strata: no memory for the block page of bundle "
                      "version %uL, using the built-in page", bundle->version);
        bundle->page = NULL;
    }

    old = ngx_http_strata_current;
    ngx_http_strata_current = bundle;

    ngx_memcpy(ngx_http_strata_current_name, ld->name, ld->name_len);
    ngx_http_strata_current_name[ld->name_len] = '\0';
    ngx_http_strata_current_name_len = ld->name_len;
    ngx_http_strata_metrics_bundle(bundle->version);

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "strata: bundle version %uL active (generation %uL)%s",
                  bundle->version, ld->generation,
                  (ld->info.flags & STRATA_BUNDLE_ROLLBACK) ? ", rollback" : "");

    (void) ngx_http_strata_check_stream(log, NGX_LOG_WARN,
                                        ngx_http_strata_smcf, bundle->engine);

    ngx_http_strata_bundle_release(old);

done:

    ngx_free(ld);
}


ngx_http_strata_bundle_t *
ngx_http_strata_bundle_acquire(void)
{
    ngx_http_strata_bundle_t  *bundle;

    bundle = ngx_http_strata_current;

    if (bundle) {
        bundle->refs++;
    }

    return bundle;
}


void
ngx_http_strata_bundle_release(ngx_http_strata_bundle_t *bundle)
{
    if (bundle == NULL || --bundle->refs > 0) {
        return;
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "strata: bundle version %uL released, unmapping",
                  bundle->version);

    /* the cycle pool cleanup must not unmap it again */
    bundle->unmapped = 1;

    ngx_http_strata_post(ngx_http_strata_unmap_handler,
                         ngx_http_strata_unmap_done, bundle);
}


/* thread pool: drop the engine, then the mapping it was reading */

static void
ngx_http_strata_unmap_handler(void *data, ngx_log_t *log)
{
    ngx_http_strata_bundle_t  *bundle = data;

    strata_engine_release(bundle->engine);
    munmap(bundle->base, bundle->len);
}


static void
ngx_http_strata_unmap_done(void *data)
{
    ngx_http_strata_bundle_t  *bundle = data;

    if (bundle->heap) {
        if (bundle->pool) {
            ngx_destroy_pool(bundle->pool);
        }

        ngx_free(bundle);
    }
}


/* the bundle's default block page, split into parts once per load */

static ngx_int_t
ngx_http_strata_bundle_page(ngx_http_strata_bundle_t *bundle, ngx_pool_t *pool)
{
    ngx_str_t     text;
    strata_str_t  html, contact;

    if (strata_engine_block_page(bundle->engine, &html, &contact)
        != STRATA_OK)
    {
        return NGX_OK;
    }

    text.data = (u_char *) html.ptr;
    text.len = html.len;

    bundle->page = ngx_http_strata_page_compile(pool, &text);
    if (bundle->page == NULL) {
        return NGX_ERROR;
    }

    bundle->contact.data = (u_char *) contact.ptr;
    bundle->contact.len = contact.len;

    return NGX_OK;
}


#if (NGX_THREADS)

static void
ngx_http_strata_task_done(ngx_event_t *ev)
{
    ngx_http_strata_task_t  *t = ev->data;

    t->done(t->task.ctx);
    ngx_free(t);
}

#endif


static void
ngx_http_strata_post(void (*handler)(void *data, ngx_log_t *log),
    ngx_http_strata_done_pt done, void *ctx)
{
#if (NGX_THREADS)
    ngx_http_strata_task_t  *t;

    if (ngx_http_strata_smcf && ngx_http_strata_smcf->thread_pool) {
        t = ngx_calloc(sizeof(ngx_http_strata_task_t), ngx_cycle->log);

        if (t) {
            t->done = done;
            t->task.ctx = ctx;
            t->task.handler = handler;
            t->task.event.handler = ngx_http_strata_task_done;
            t->task.event.data = t;

            if (ngx_thread_task_post(ngx_http_strata_smcf->thread_pool,
                                     &t->task)
                == NGX_OK)
            {
                return;
            }

            ngx_free(t);
        }
    }
#endif

    /* no thread pool: run here, in the event loop */

    handler(ctx, ngx_cycle->log);
    done(ctx);
}
