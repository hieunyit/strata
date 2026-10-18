/*
 * Directives, configuration merge and module initialization.
 */

#include "ngx_http_strata_module.h"


static ngx_int_t ngx_http_strata_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_strata_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_strata_init_process(ngx_cycle_t *cycle);
static void ngx_http_strata_exit_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_strata_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_strata_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_strata_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_strata_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_strata_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_strata_event_socket(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_strata_block_page(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_enum_t  ngx_http_strata_modes[] = {
    { ngx_string("inherit"), NGX_HTTP_STRATA_MODE_INHERIT },
    { ngx_string("shadow"), NGX_HTTP_STRATA_MODE_SHADOW },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_strata_fail_modes[] = {
    { ngx_string("open"), NGX_HTTP_STRATA_FAIL_OPEN },
    { ngx_string("closed"), NGX_HTTP_STRATA_FAIL_CLOSED },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_strata_breaker_actions[] = {
    { ngx_string("degrade"), NGX_HTTP_STRATA_BREAKER_DEGRADE },
    { ngx_string("reject"), NGX_HTTP_STRATA_BREAKER_REJECT },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_strata_body_modes[] = {
    { ngx_string("buffer"), NGX_HTTP_STRATA_BODY_BUFFER },
    { ngx_string("stream"), NGX_HTTP_STRATA_BODY_STREAM },
    { ngx_null_string, 0 }
};


#define NGX_HTTP_STRATA_ANY_CONF                                             \
    (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF)


static ngx_command_t  ngx_http_strata_commands[] = {

    { ngx_string("strata"),
      NGX_HTTP_STRATA_ANY_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_strata_loc_conf_t, enable),
      NULL },

    { ngx_string("strata_control_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_strata_main_conf_t, control_file),
      NULL },

    { ngx_string("strata_bundle_dir"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_strata_main_conf_t, bundle_dir),
      NULL },

    { ngx_string("strata_bundle_pubkey"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_strata_main_conf_t, pubkey_file),
      NULL },

    { ngx_string("strata_bundle_check"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_strata_main_conf_t, bundle_check),
      NULL },

    { ngx_string("strata_node_id"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_strata_main_conf_t, node_id),
      NULL },

    { ngx_string("strata_event_socket"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_strata_event_socket,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("strata_metrics_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_strata_main_conf_t, metrics_file),
      NULL },

    { ngx_string("strata_policy"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_strata_loc_conf_t, policy),
      NULL },

    { ngx_string("strata_mode"),
      NGX_HTTP_STRATA_ANY_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_strata_loc_conf_t, mode),
      &ngx_http_strata_modes },

    { ngx_string("strata_fail_mode"),
      NGX_HTTP_STRATA_ANY_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_strata_loc_conf_t, fail_mode),
      &ngx_http_strata_fail_modes },

    { ngx_string("strata_request_body_mode"),
      NGX_HTTP_STRATA_ANY_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_strata_loc_conf_t, body_mode),
      &ngx_http_strata_body_modes },

    { ngx_string("strata_request_body_limit"),
      NGX_HTTP_STRATA_ANY_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_strata_loc_conf_t, body_limit),
      NULL },

    { ngx_string("strata_response_inspect"),
      NGX_HTTP_STRATA_ANY_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_strata_loc_conf_t, response_inspect),
      NULL },

    { ngx_string("strata_response_body_limit"),
      NGX_HTTP_STRATA_ANY_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_strata_loc_conf_t, response_body_limit),
      NULL },

    { ngx_string("strata_identity"),
      NGX_HTTP_STRATA_ANY_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_strata_loc_conf_t, identity),
      NULL },

    { ngx_string("strata_block_page"),
      NGX_HTTP_STRATA_ANY_CONF|NGX_CONF_TAKE1,
      ngx_http_strata_block_page,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("strata_cpu_budget"),
      NGX_HTTP_STRATA_ANY_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_strata_loc_conf_t, cpu_budget),
      NULL },

    { ngx_string("strata_breaker"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_strata_main_conf_t, breaker),
      NULL },

    { ngx_string("strata_breaker_threshold"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3|NGX_CONF_TAKE4,
      ngx_http_strata_breaker_threshold,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("strata_breaker_action"),
      NGX_HTTP_STRATA_ANY_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_strata_loc_conf_t, breaker_action),
      &ngx_http_strata_breaker_actions },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_strata_module_ctx = {
    ngx_http_strata_preconfiguration,      /* preconfiguration */
    ngx_http_strata_postconfiguration,     /* postconfiguration */

    ngx_http_strata_create_main_conf,      /* create main configuration */
    ngx_http_strata_init_main_conf,        /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_strata_create_loc_conf,       /* create location configuration */
    ngx_http_strata_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_strata_module = {
    NGX_MODULE_V1,
    &ngx_http_strata_module_ctx,           /* module context */
    ngx_http_strata_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_http_strata_init_module,           /* init module */
    ngx_http_strata_init_process,          /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_strata_exit_process,          /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_strata_default_page = ngx_string(
"<!DOCTYPE html>" CRLF
"<html><head><meta charset=\"utf-8\"><title>Request blocked</title></head>"
CRLF
"<body><h1>Request blocked</h1>" CRLF
"<p>Your request was blocked by the web application firewall.</p>" CRLF
"<p>Block ID: <code>{{block_id}}</code><br>Time: {{time}}</p>" CRLF
"<p>{{support_contact}}</p>" CRLF
"</body></html>" CRLF
);


#if (NGX_HTTP_SSL)
int  ngx_http_strata_ssl_ja4_index = -1;

static void
ngx_http_strata_ssl_msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    ngx_connection_t  *c;
    u_char            *ja4;
    (void) version;
    (void) arg;

    if (write_p != 0 || content_type != 22 /* SSL3_RT_HANDSHAKE */ || len == 0) {
        return;
    }

    if (((const uint8_t *) buf)[0] != 1 /* SSL3_MT_CLIENT_HELLO */) {
        return;
    }

    c = ngx_ssl_get_connection(ssl);
    if (c == NULL || c->pool == NULL) {
        return;
    }

    if (SSL_get_ex_data(ssl, ngx_http_strata_ssl_ja4_index) != NULL) {
        return;
    }

    ja4 = ngx_palloc(c->pool, STRATA_JA4_LEN + 1);
    if (ja4 == NULL) {
        return;
    }

    if (strata_calc_ja4(buf, len, 0, (char *) ja4, STRATA_JA4_LEN + 1) == STRATA_OK) {
        SSL_set_ex_data(ssl, ngx_http_strata_ssl_ja4_index, ja4);
    }
}
#endif


static ngx_int_t
ngx_http_strata_preconfiguration(ngx_conf_t *cf)
{
    return ngx_http_strata_add_variables(cf);
}


static ngx_int_t
ngx_http_strata_init_module(ngx_cycle_t *cycle)
{
    ngx_http_strata_main_conf_t  *smcf;

    smcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_strata_module);

    if (smcf != NULL && smcf->enabled && !ngx_test_config) {
        ngx_http_strata_metrics_create(cycle, smcf);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_strata_init_process(ngx_cycle_t *cycle)
{
    ngx_http_strata_main_conf_t  *smcf;

    if (ngx_http_strata_bundle_init_process(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    smcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_strata_module);

    if (smcf != NULL && smcf->enabled) {
        ngx_http_strata_events_init_process(cycle, smcf);
        ngx_http_strata_breaker_init_process();
    }

    return NGX_OK;
}


static void
ngx_http_strata_exit_process(ngx_cycle_t *cycle)
{
    ngx_http_strata_bundle_exit_process(cycle);
    ngx_http_strata_events_exit_process();
}


static ngx_int_t
ngx_http_strata_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt          *h;
    ngx_http_core_main_conf_t    *cmcf;
    ngx_http_strata_main_conf_t  *smcf;

    if (strata_abi_version() >> 16 != STRATA_ABI_VERSION_MAJOR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "strata: libstrata ABI %uD.%uD, module expects %d.x",
                           strata_abi_version() >> 16,
                           strata_abi_version() & 0xffff,
                           STRATA_ABI_VERSION_MAJOR);
        return NGX_ERROR;
    }

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_strata_module);

    if (!smcf->enabled) {
        return NGX_OK;
    }

    if (ngx_http_strata_bundle_init(cf, smcf) != NGX_OK) {
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_strata_preaccess_handler;

#if (NGX_HTTP_SSL)
    {
        ngx_uint_t                   s;
        ngx_http_core_srv_conf_t   **cscfp;
        ngx_http_ssl_srv_conf_t     *sscf;

        if (ngx_http_strata_ssl_ja4_index == -1) {
            ngx_http_strata_ssl_ja4_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        }

        cscfp = cmcf->servers.elts;
        for (s = 0; s < cmcf->servers.nelts; s++) {
            sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
            if (sscf != NULL && sscf->ssl.ctx != NULL) {
                SSL_CTX_set_msg_callback(sscf->ssl.ctx, ngx_http_strata_ssl_msg_cb);
            }
        }
    }
#endif

    return ngx_http_strata_filter_init(cf);
}


static void *
ngx_http_strata_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_strata_main_conf_t  *smcf;

    smcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_strata_main_conf_t));
    if (smcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     smcf->control_file = { 0, NULL };
     *     smcf->bundle_dir = { 0, NULL };
     *     smcf->pubkey_file = { 0, NULL };
     *     smcf->node_id = { 0, NULL };
     *     smcf->event_socket = { 0, NULL };
     *     smcf->enabled = 0;
     *     smcf->bundle = NULL;
     */

    smcf->bundle_check = NGX_CONF_UNSET_MSEC;
    smcf->request_id_index = NGX_ERROR;
    smcf->breaker = NGX_CONF_UNSET;
    smcf->breaker_window = NGX_CONF_UNSET_MSEC;

    return smcf;
}


static char *
ngx_http_strata_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_strata_main_conf_t *smcf = conf;

    ngx_str_t  name = ngx_string("request_id");

    if (smcf->control_file.data == NULL) {
        ngx_str_set(&smcf->control_file, "/run/strata/control");
    }

    if (smcf->bundle_dir.data == NULL) {
        ngx_str_set(&smcf->bundle_dir, "/var/lib/strata/bundle");
    }

    if (smcf->event_socket.data == NULL) {
        ngx_str_set(&smcf->event_socket, "unix:/run/strata/events.sock");
    }

    if (smcf->metrics_file.data == NULL) {
        ngx_str_set(&smcf->metrics_file, "/run/strata/metrics");
    }

    if (smcf->node_id.data == NULL) {
        smcf->node_id = cf->cycle->hostname;
    }

    ngx_conf_init_msec_value(smcf->bundle_check, 1000);

    /* nginx-module.md: 2% within 10 s, at least 200 requests; open 30 s */
    ngx_conf_init_value(smcf->breaker, 1);
    if (smcf->breaker_window == NGX_CONF_UNSET_MSEC) {
        smcf->breaker_share = 200;
        smcf->breaker_window = 10000;
        smcf->breaker_min = 200;
    }
    if (smcf->breaker_open == 0) {
        smcf->breaker_open = 30000;
    }

    smcf->default_page = ngx_http_strata_page_compile(cf->pool,
                                                 &ngx_http_strata_default_page);
    if (smcf->default_page == NULL) {
        return NGX_CONF_ERROR;
    }

    /* $request_id is attached to events when the core provides it */
    smcf->request_id_index = ngx_http_get_variable_index(cf, &name);
    if (smcf->request_id_index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_strata_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_strata_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_strata_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     slcf->policy = { 0, NULL };
     */

    slcf->enable = NGX_CONF_UNSET;
    slcf->mode = NGX_CONF_UNSET_UINT;
    slcf->fail_mode = NGX_CONF_UNSET_UINT;
    slcf->body_mode = NGX_CONF_UNSET_UINT;
    slcf->body_limit = NGX_CONF_UNSET_SIZE;
    slcf->response_inspect = NGX_CONF_UNSET;
    slcf->response_body_limit = NGX_CONF_UNSET_SIZE;
    slcf->identity = NGX_CONF_UNSET_PTR;
    slcf->block_page = NGX_CONF_UNSET_PTR;
    slcf->cpu_budget = NGX_CONF_UNSET_MSEC;
    slcf->breaker_action = NGX_CONF_UNSET_UINT;

    return slcf;
}


static char *
ngx_http_strata_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_strata_loc_conf_t *prev = parent;
    ngx_http_strata_loc_conf_t *conf = child;

    ngx_http_core_loc_conf_t      *clcf;
    ngx_http_strata_main_conf_t   *smcf;
    ngx_http_strata_stream_loc_t  *sl;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->policy, prev->policy, "");
    ngx_conf_merge_uint_value(conf->mode, prev->mode,
                              NGX_HTTP_STRATA_MODE_INHERIT);
    ngx_conf_merge_uint_value(conf->fail_mode, prev->fail_mode,
                              NGX_HTTP_STRATA_FAIL_OPEN);
    ngx_conf_merge_uint_value(conf->body_mode, prev->body_mode,
                              NGX_HTTP_STRATA_BODY_BUFFER);
    ngx_conf_merge_size_value(conf->body_limit, prev->body_limit,
                              (size_t) 1024 * 1024);
    ngx_conf_merge_value(conf->response_inspect, prev->response_inspect, 1);
    ngx_conf_merge_size_value(conf->response_body_limit,
                              prev->response_body_limit, (size_t) 512 * 1024);
    ngx_conf_merge_ptr_value(conf->identity, prev->identity, NULL);
    ngx_conf_merge_ptr_value(conf->block_page, prev->block_page, NULL);
    ngx_conf_merge_msec_value(conf->cpu_budget, prev->cpu_budget, 10);
    ngx_conf_merge_uint_value(conf->breaker_action, prev->breaker_action,
                              NGX_HTTP_STRATA_BREAKER_DEGRADE);

    if (!conf->enable) {
        return NGX_CONF_OK;
    }

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_strata_module);
    smcf->enabled = 1;

    /*
     * "stream" is shadow only: remember the location so that its policy's
     * signed mode is checked once the bundle is mapped ("nginx -t" fails if
     * it enforces).
     */

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (conf->body_mode == NGX_HTTP_STRATA_BODY_STREAM
        && conf->policy.len && clcf->name.len)
    {
        if (smcf->stream_locs == NULL) {
            smcf->stream_locs = ngx_array_create(cf->pool, 4,
                                         sizeof(ngx_http_strata_stream_loc_t));
            if (smcf->stream_locs == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        sl = ngx_array_push(smcf->stream_locs);
        if (sl == NULL) {
            return NGX_CONF_ERROR;
        }

        sl->policy = conf->policy;
        sl->location = clcf->name;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_strata_event_socket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_strata_main_conf_t *smcf = conf;

    ngx_str_t  *value;

    if (smcf->event_socket.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len <= sizeof("unix:") - 1
        || ngx_strncmp(value[1].data, "unix:", sizeof("unix:") - 1) != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid event socket \"%V\", expected unix:<path>",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    smcf->event_socket = value[1];

    return NGX_CONF_OK;
}


static char *
ngx_http_strata_block_page(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_strata_loc_conf_t *slcf = conf;

    off_t            size;
    ssize_t          n;
    ngx_fd_t         fd;
    ngx_str_t       *value, name, text;
    ngx_file_t       file;
    ngx_file_info_t  fi;

    if (slcf->block_page != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;
    name = value[1];

    if (ngx_conf_full_name(cf->cycle, &name, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    fd = ngx_open_file(name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", &name);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name = name;
    file.log = cf->log;

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", &name);
        goto failed;
    }

    size = ngx_file_size(&fi);

    if (size <= 0 || size > NGX_HTTP_STRATA_PAGE_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "block page \"%V\" must be 1..%d bytes",
                           &name, NGX_HTTP_STRATA_PAGE_MAX);
        goto failed;
    }

    text.len = (size_t) size;
    text.data = ngx_pnalloc(cf->pool, text.len);
    if (text.data == NULL) {
        goto failed;
    }

    n = ngx_read_file(&file, text.data, text.len, 0);
    if (n != (ssize_t) text.len) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "short read of block page \"%V\"", &name);
        goto failed;
    }

    ngx_close_file(fd);

    slcf->block_page = ngx_http_strata_page_compile(cf->pool, &text);
    if (slcf->block_page == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

failed:

    ngx_close_file(fd);
    return NGX_CONF_ERROR;
}
