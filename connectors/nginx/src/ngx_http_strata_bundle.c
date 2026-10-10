/*
 * Bundle loading at configuration time.
 *
 * The master maps <strata_bundle_dir>/current.sbn read-only and shared while
 * reading the configuration; workers inherit the mapping through fork(), so
 * all of them share one copy in physical memory. A missing bundle is only a
 * warning (requests then follow strata_fail_mode); a bundle libstrata rejects
 * makes "nginx -t" fail.
 *
 * TODO(hot reload): control file timer, thread pool loading, engine swap.
 */

#include "ngx_http_strata_module.h"

#include <sys/mman.h>


static ngx_int_t ngx_http_strata_read_pubkey(ngx_conf_t *cf, ngx_str_t *path,
    u_char *key);
static void ngx_http_strata_bundle_cleanup(void *data);


ngx_int_t
ngx_http_strata_bundle_init(ngx_conf_t *cf, ngx_http_strata_main_conf_t *smcf)
{
    off_t                      size;
    u_char                    *base, *p;
    ngx_fd_t                   fd;
    ngx_err_t                  err;
    ngx_str_t                  path;
    strata_err_t               serr;
    ngx_file_info_t            fi;
    ngx_pool_cleanup_t        *cln;
    strata_engine_t           *engine;
    ngx_http_strata_bundle_t  *bundle;
    u_char                     key[STRATA_PUBKEY_LEN];

    if (smcf->pubkey_file.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"strata_bundle_pubkey\" is required when "
                           "\"strata\" is enabled");
        return NGX_ERROR;
    }

    if (ngx_conf_full_name(cf->cycle, &smcf->pubkey_file, 1) != NGX_OK
        || ngx_conf_full_name(cf->cycle, &smcf->bundle_dir, 1) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_strata_read_pubkey(cf, &smcf->pubkey_file, key) != NGX_OK) {
        return NGX_ERROR;
    }

    path.len = smcf->bundle_dir.len + sizeof("/" NGX_HTTP_STRATA_BUNDLE_FILE);
    path.data = ngx_pnalloc(cf->pool, path.len);
    if (path.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(path.data, smcf->bundle_dir.data, smcf->bundle_dir.len);
    ngx_memcpy(p, "/" NGX_HTTP_STRATA_BUNDLE_FILE,
               sizeof("/" NGX_HTTP_STRATA_BUNDLE_FILE));
    path.len--;

    fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        ngx_conf_log_error(NGX_LOG_WARN, cf, err,
                           "strata: no bundle at \"%V\", requests follow "
                           "strata_fail_mode", &path);
        return NGX_OK;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", &path);
        goto failed;
    }

    size = ngx_file_size(&fi);
    if (size <= 0 || (uint64_t) size > (uint64_t) NGX_MAX_SIZE_T_VALUE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "strata: bundle \"%V\" has invalid size %O",
                           &path, size);
        goto failed;
    }

    base = mmap(NULL, (size_t) size, PROT_READ, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "mmap(\"%V\") failed", &path);
        goto failed;
    }

    ngx_close_file(fd);

    ngx_memzero(&serr, sizeof(strata_err_t));
    engine = strata_engine_map(base, (size_t) size, key, &serr);
    if (engine == NULL) {
        serr.msg[STRATA_ERR_MSG_SIZE - 1] = '\0';
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "strata: bundle \"%V\" rejected (%d): %s",
                           &path, serr.code, serr.msg);
        munmap(base, (size_t) size);
        return NGX_ERROR;
    }

    bundle = ngx_palloc(cf->pool, sizeof(ngx_http_strata_bundle_t));
    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (bundle == NULL || cln == NULL) {
        strata_engine_release(engine);
        munmap(base, (size_t) size);
        return NGX_ERROR;
    }

    bundle->engine = engine;
    bundle->base = base;
    bundle->len = (size_t) size;

    cln->handler = ngx_http_strata_bundle_cleanup;
    cln->data = bundle;

    smcf->bundle = bundle;

    ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                  "strata: bundle \"%V\" mapped, %uz bytes", &path, bundle->len);

    return NGX_OK;

failed:

    ngx_close_file(fd);
    return NGX_ERROR;
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


static void
ngx_http_strata_bundle_cleanup(void *data)
{
    ngx_http_strata_bundle_t  *bundle = data;

    /*
     * Runs when the configuration cycle is destroyed. Transactions hold
     * their own engine reference; a worker only drops a cycle once its
     * requests are done, so nothing still reads the mapping here.
     */

    strata_engine_release(bundle->engine);
    munmap(bundle->base, bundle->len);
}
