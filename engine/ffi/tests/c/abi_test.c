#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200112L
/*
 * C-side ABI test for libstrata: layout, version, NULL/idempotency rules,
 * stub behaviour and Block ID format, exercised through strata.h exactly as
 * a connector would.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "strata.h"

/* Layout is part of the ABI: these must never change within a major. */
_Static_assert(sizeof(strata_str_t) == 2 * sizeof(void *), "strata_str_t");
_Static_assert(offsetof(strata_str_t, len) == sizeof(void *), "strata_str_t.len");
_Static_assert(sizeof(strata_str_pair_t) == 2 * sizeof(strata_str_t), "pair");
_Static_assert(sizeof(strata_header_t) == sizeof(strata_str_pair_t), "header");
_Static_assert(offsetof(strata_verdict_t, action) == 0, "verdict.action");
_Static_assert(offsetof(strata_verdict_t, status) == 4, "verdict.status");
_Static_assert(offsetof(strata_verdict_t, flags) == 6, "verdict.flags");
_Static_assert(offsetof(strata_verdict_t, error) == 8, "verdict.error");
_Static_assert(offsetof(strata_verdict_t, score) == 12, "verdict.score");
_Static_assert(offsetof(strata_verdict_t, n_rules) == 16, "verdict.n_rules");
_Static_assert(offsetof(strata_verdict_t, rules) == 20, "verdict.rules");
_Static_assert(offsetof(strata_verdict_t, block_id) == 20 + 4 * STRATA_MAX_RULES,
               "verdict.block_id");
_Static_assert(sizeof(strata_verdict_t) == 108, "verdict size");
_Static_assert(STRATA_BLOCK_ID_SIZE == 24, "block id size");
_Static_assert(STRATA_MAX_RULES == 16, "max rules");
_Static_assert(sizeof(strata_rc_t) == 4, "rc");
_Static_assert(STRATA_ABI_VERSION_MAJOR == 1, "abi major");
_Static_assert(sizeof(strata_engine_info_t) == 24, "engine info size");
_Static_assert(offsetof(strata_engine_info_t, flags) == 16, "engine info.flags");
_Static_assert(sizeof(strata_policy_info_t) == 8, "policy info size");

static int failures;

#define CHECK(c)                                                          \
    do {                                                                  \
        if (!(c)) {                                                       \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,        \
                    __LINE__, #c);                                        \
            failures++;                                                   \
        }                                                                 \
    } while (0)

#define S(lit) ((strata_str_t) { (const uint8_t *) (lit), sizeof(lit) - 1 })

static uint8_t   pubkey[STRATA_PUBKEY_LEN];
static uint8_t  *bundle;
static size_t    bundle_len;

static uint8_t *
slurp(const char *path, size_t *len)
{
    FILE     *f;
    long      n;
    uint8_t  *p;

    f = fopen(path, "rb");
    if (f == NULL || fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) <= 0
        || fseek(f, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "cannot read %s\n", path);
        exit(2);
    }
    /* page-aligned, like a connector's mmap: the Hyperscan image in the
       bundle needs it */
    if (posix_memalign((void **) &p, 4096, (size_t) n) != 0
        || fread(p, 1, (size_t) n, f) != (size_t) n)
    {
        exit(2);
    }
    fclose(f);
    *len = (size_t) n;
    return p;
}

static int
id_ok(const char *id, const char *prefix)
{
    static const char alphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    size_t i;

    if (strlen(id) != 23 || strncmp(id, prefix, 4) != 0) {
        return 0;
    }
    for (i = 4; i < 23; i++) {
        if (i == 8 || i == 13 || i == 18) {
            if (id[i] != '-') {
                return 0;
            }
        } else if (id[i] == '\0' || strchr(alphabet, id[i]) == NULL) {
            return 0;
        }
    }
    return 1;
}

static strata_tx_t *
start(strata_engine_t *e, uint32_t flags, strata_str_t uri)
{
    strata_conn_t     conn;
    strata_tx_t      *tx;
    strata_header_t   h[2];

    memset(&conn, 0, sizeof(conn));
    conn.client_addr = S("192.0.2.10");
    conn.node_id = S("web-01");
    conn.flags = flags;

    tx = strata_tx_new(e, S("example-api"), &conn, 2000);
    CHECK(tx != NULL);

    CHECK(strata_tx_request_line(tx, S("POST"), uri, uri, S(""), S("HTTP/1.1"))
          == (e ? STRATA_OK : STRATA_E_BUNDLE));

    h[0].key = S("Host");
    h[0].val = S("api.example.test");
    h[1].key = S("Accept");
    h[1].val = S("application/json");
    strata_tx_request_headers(tx, h, 2);
    return tx;
}

int
main(int argc, char **argv)
{
    size_t                 klen;
    uint8_t               *key, *bad;
    strata_err_t           err;
    strata_engine_t       *e;
    strata_engine_info_t   info;
    strata_policy_info_t   pol;
    strata_str_t           html, contact;
    strata_tx_t      *tx;
    strata_verdict_t  v;
    strata_buf_t      buf;

    /* argv: a signed bundle (version 1, 3 policies) and its public key */
    if (argc != 3) {
        fprintf(stderr, "usage: abi_test <bundle.sbn> <bundle.pub>\n");
        return 2;
    }
    bundle = slurp(argv[1], &bundle_len);
    key = slurp(argv[2], &klen);
    if (klen != STRATA_PUBKEY_LEN) {
        return 2;
    }
    memcpy(pubkey, key, klen);
    free(key);

    CHECK(strata_abi_version() == STRATA_ABI_VERSION);
    CHECK(strata_abi_version() >> 16 == STRATA_ABI_VERSION_MAJOR);

    /* engine_map errors */
    memset(&err, 0, sizeof(err));
    CHECK(strata_engine_map((const uint8_t *) "XXXX", 4, pubkey, &err) == NULL);
    CHECK(err.code == STRATA_E_BUNDLE && err.msg[0] != '\0');
    CHECK(strata_engine_map(NULL, 10, pubkey, &err) == NULL);
    CHECK(err.code == STRATA_E_INVALID);
    CHECK(strata_engine_map(bundle, bundle_len, NULL, NULL) == NULL);

    /* one flipped byte breaks the signature */
    bad = malloc(bundle_len);
    if (bad == NULL) {
        return 2;
    }
    memcpy(bad, bundle, bundle_len);
    bad[100] ^= 1;
    CHECK(strata_engine_map(bad, bundle_len, pubkey, &err) == NULL);
    CHECK(err.code == STRATA_E_BUNDLE && strstr(err.msg, "signature") != NULL);
    free(bad);

    e = strata_engine_map(bundle, bundle_len, pubkey, &err);
    CHECK(e != NULL && err.code == STRATA_OK);

    strata_engine_info(e, &info);
    CHECK(info.version == 1 && info.n_policies == 4 && info.flags == 0);
    CHECK(info.created_at_ms == 1760000000000ULL);
    strata_engine_info(NULL, &info);
    CHECK(info.version == 0);
    strata_engine_info(e, NULL);

    /* policies and their signed modes, read in place */
    CHECK(strata_engine_policy(e, S("example-api"), &pol) == STRATA_OK);
    CHECK(pol.mode == STRATA_POLICY_ENFORCE && pol.index == 0);
    CHECK(strata_engine_policy(e, S("example-web"), &pol) == STRATA_OK);
    CHECK(pol.mode == STRATA_POLICY_SHADOW && pol.index == 2);
    CHECK(strata_engine_policy(e, S("example"), &pol) == STRATA_E_NOT_FOUND);
    CHECK(strata_engine_policy(e, S(""), &pol) == STRATA_E_NOT_FOUND);
    CHECK(strata_engine_policy(NULL, S("example-api"), &pol) == STRATA_E_INVALID);
    CHECK(strata_engine_policy(e, S("example-api"), NULL) == STRATA_E_INVALID);

    /* kill switch list (1.3): arguments; what it skips is tested in Rust */
    {
        static uint32_t many[4097];
        uint32_t ids[2] = { 942100, 941100 };

        CHECK(strata_engine_disable_rules(e, ids, 2) == STRATA_OK);
        CHECK(strata_engine_disable_rules(e, NULL, 0) == STRATA_OK);
        CHECK(strata_engine_disable_rules(NULL, ids, 2) == STRATA_E_INVALID);
        CHECK(strata_engine_disable_rules(e, NULL, 1) == STRATA_E_INVALID);
        for (size_t i = 0; i < 4097; i++) {
            many[i] = (uint32_t) i + 1;
        }
        CHECK(strata_engine_disable_rules(e, many, 4097) == STRATA_E_INVALID);
        CHECK(strata_engine_disable_rules(e, many, 4096) == STRATA_OK);
        CHECK(strata_engine_disable_rules(e, NULL, 0) == STRATA_OK);
    }

    /* replay sampling (1.5): arguments; the sample itself is tested in Rust */
    {
        uint8_t key[32];

        memset(key, 0x5a, sizeof(key));
        CHECK(strata_engine_set_replay(e, S("k1"), key, 32, 10000) == STRATA_OK);
        CHECK(strata_engine_set_replay(e, S("k1"), key, 31, 10000) == STRATA_E_INVALID);
        CHECK(strata_engine_set_replay(e, S("k1"), NULL, 32, 100) == STRATA_E_INVALID);
        CHECK(strata_engine_set_replay(e, S("k1"), key, 32, 10001) == STRATA_E_INVALID);
        CHECK(strata_engine_set_replay(NULL, S("k1"), key, 32, 100) == STRATA_E_INVALID);
        CHECK(strata_engine_set_replay(e, S(""), NULL, 0, 0) == STRATA_OK);
        CHECK(strata_tx_sample(NULL, NULL, 0) == 0);
    }

    /* default block page, read in place from the bundle */
    CHECK(strata_engine_block_page(e, &html, &contact) == STRATA_OK);
    CHECK(html.len > 0 && memmem(html.ptr, html.len, "{{block_id}}", 12) != NULL);
    CHECK(html.ptr >= bundle && html.ptr + html.len <= bundle + bundle_len);
    CHECK(contact.len > 0 && contact.ptr >= bundle);
    CHECK(strata_engine_block_page(NULL, &html, &contact) == STRATA_E_INVALID);
    CHECK(strata_engine_block_page(e, NULL, &contact) == STRATA_E_INVALID);
    strata_engine_retain(e);
    strata_engine_release(e);

    /* NULL handles are rejected, never crash */
    CHECK(strata_tx_request_line(NULL, S(""), S(""), S(""), S(""), S(""))
          == STRATA_E_INVALID);
    CHECK(strata_tx_request_headers(NULL, NULL, 0) == STRATA_E_INVALID);
    CHECK(strata_tx_request_body_chunk(NULL, NULL, 0, 1) == STRATA_E_INVALID);
    strata_tx_verdict(NULL, &v);
    CHECK(v.error == STRATA_E_INVALID);
    strata_tx_verdict(NULL, NULL);
    strata_tx_free(NULL);
    strata_buf_free(NULL);
    CHECK(strata_tx_event(NULL, NULL, 0) == 0);

    /* NULL with len > 0 is invalid, and any error is sticky */
    tx = start(e, 0, S("/index.html"));
    CHECK(strata_tx_request_body_chunk(tx, NULL, 5, 0) == STRATA_E_INVALID);
    CHECK(strata_tx_request_body_chunk(tx, (const uint8_t *) "ok", 2, 1)
          == STRATA_E_INVALID);
    strata_tx_verdict(tx, &v);
    CHECK(v.error == STRATA_E_INVALID && id_ok(v.block_id, "EVT-"));
    strata_tx_free(tx);

    /* calls out of order break the transaction too */
    tx = start(e, 0, S("/index.html"));
    CHECK(strata_tx_response_body_chunk(tx, NULL, 0, 1, NULL) == STRATA_E_STATE);
    strata_tx_verdict(tx, &v);
    CHECK(v.error == STRATA_E_STATE);
    strata_tx_free(tx);
    tx = start(e, 0, S("/index.html"));
    CHECK(strata_tx_response_body_flush(tx, &buf) == STRATA_E_STATE);
    CHECK(buf.ptr == NULL);
    strata_tx_free(tx);

    /* ptr may be NULL when len == 0 */
    tx = start(e, 0, S("/index.html"));
    CHECK(strata_tx_request_body_chunk(tx, NULL, 0, 0) == STRATA_OK);
    strata_tx_verdict(tx, &v);
    CHECK(v.action == STRATA_ACTION_ALLOW && v.error == STRATA_OK);
    CHECK(v.flags & STRATA_VF_NEED_BODY);
    CHECK(v.flags & STRATA_VF_JSON);
    CHECK(strata_tx_request_body_chunk(tx, (const uint8_t *) "a=1", 3, 1) == STRATA_OK);
    strata_tx_verdict(tx, &v);
    CHECK(!(v.flags & STRATA_VF_NEED_BODY) && v.block_id[0] == '\0');

    /* response side; free is idempotent */
    CHECK(strata_tx_response_headers(tx, 200, NULL, 0) == STRATA_OK);
    memset(&buf, 0xff, sizeof(buf));
    CHECK(strata_tx_response_body_chunk(tx, (const uint8_t *) "ok", 2, 1, &buf)
          == STRATA_OK);
#ifdef STRATA_TEST_HOOKS
    /* the test data guard rewrites every chunk */
    CHECK(buf.ptr != NULL && buf.len == 2 && memcmp(buf.ptr, "ok", 2) == 0);
#else
    CHECK(buf.ptr == NULL && buf.len == 0);
#endif
    strata_buf_free(&buf);
    CHECK(buf.ptr == NULL);
    strata_buf_free(&buf);
    memset(&buf, 0xff, sizeof(buf));
    CHECK(strata_tx_response_body_flush(tx, &buf) == STRATA_OK);
#ifndef STRATA_TEST_HOOKS
    CHECK(buf.ptr == NULL && buf.len == 0);   /* no data guard, nothing held */
#endif
    strata_buf_free(&buf);

    strata_tx_free(tx);
    tx = NULL;
    strata_tx_free(tx);              /* idempotent with the NULL convention */

    /* block on URI */
    tx = start(e, 0, S("/search?q=STRATA-TEST-BLOCK"));
    strata_tx_verdict(tx, &v);
    CHECK(v.action == STRATA_ACTION_BLOCK && v.status == 403);
    CHECK(strata_tx_time_us(tx) < 1000000);
    CHECK(strata_tx_time_us(NULL) == 0);
    CHECK(v.n_rules == 1 && v.score > 0);
    CHECK(id_ok(v.block_id, "STR-"));
    printf("block id: %s\n", v.block_id);
    strata_tx_free(tx);

    /* block on body split across chunks */
    tx = start(e, 0, S("/upload"));
    CHECK(strata_tx_request_body_chunk(tx, (const uint8_t *) "xxSTRATA-TE", 11, 0) == STRATA_OK);
    CHECK(strata_tx_request_body_chunk(tx, (const uint8_t *) "ST-BLOCKyy", 10, 1) == STRATA_OK);
    strata_tx_verdict(tx, &v);
    CHECK(v.action == STRATA_ACTION_BLOCK && id_ok(v.block_id, "STR-"));
    strata_tx_free(tx);

    /* shadow: log with Event ID */
    tx = start(e, STRATA_TXF_FORCE_SHADOW, S("/STRATA-TEST-BLOCK"));
    strata_tx_verdict(tx, &v);
    CHECK(v.action == STRATA_ACTION_LOG && id_ok(v.block_id, "EVT-"));
    strata_tx_free(tx);

    /* no engine: bundle error with Event ID */
    tx = start(NULL, 0, S("/"));
    strata_tx_verdict(tx, &v);
    CHECK(v.error == STRATA_E_BUNDLE && id_ok(v.block_id, "EVT-"));
    strata_tx_free(tx);

#ifdef STRATA_TEST_HOOKS
    /* a panic is caught, reported, and makes the transaction sticky-broken */
    tx = start(e, 0, S("/"));
    CHECK(strata_tx_request_body_chunk(tx, (const uint8_t *) "STRATA-TEST-PANIC", 17, 1)
          == STRATA_E_INTERNAL);
    CHECK(strata_tx_request_body_chunk(tx, NULL, 0, 1) == STRATA_E_INTERNAL);
    strata_tx_verdict(tx, &v);
    CHECK(v.error == STRATA_E_INTERNAL && id_ok(v.block_id, "EVT-"));
    strata_tx_free(tx);

    /* data guard: a needle split across chunks is masked, the tail of each
       chunk is held back, the totals add up and the last call flushes */
    tx = start(e, 0, S("/"));
    strata_tx_verdict(tx, &v);
    CHECK(v.flags & STRATA_VF_NEED_RESPONSE);
    CHECK(strata_tx_response_headers(tx, 200, NULL, 0) == STRATA_OK);
    {
        static const char  *parts[] = { "a STRATA-TE", "ST-MA", "SK b", "" };
        char                 out[64];
        size_t               i, total = 0;

        for (i = 0; i < 4; i++) {
            size_t  len = strlen(parts[i]);

            CHECK(strata_tx_response_body_chunk(tx, len ? (const uint8_t *) parts[i] : NULL,
                                                len, i == 3, &buf) == STRATA_OK);
            CHECK(buf.ptr != NULL && total + buf.len <= sizeof(out));
            memcpy(out + total, buf.ptr, buf.len);
            total += buf.len;
            strata_buf_free(&buf);
        }
        CHECK(total == 20 && memcmp(out, "a **************** b", 20) == 0);
    }
    /* rewritten == NULL while the guard needs to rewrite is invalid */
    strata_tx_free(tx);
    tx = start(e, 0, S("/"));
    CHECK(strata_tx_response_headers(tx, 200, NULL, 0) == STRATA_OK);
    CHECK(strata_tx_response_body_chunk(tx, (const uint8_t *) "x", 1, 1, NULL)
          == STRATA_E_INVALID);
    strata_tx_free(tx);

    /* flush (ABI 1.1): a short message is held back by the chunk call and
       sent by the flush; nothing is left for the last call */
    tx = start(e, 0, S("/events"));
    CHECK(strata_tx_response_headers(tx, 200, NULL, 0) == STRATA_OK);
    CHECK(strata_tx_response_body_chunk(tx, (const uint8_t *) "data: 1\n\n", 9, 0, &buf)
          == STRATA_OK);
    CHECK(buf.ptr != NULL && buf.len == 0);
    strata_buf_free(&buf);
    CHECK(strata_tx_response_body_flush(tx, &buf) == STRATA_OK);
    CHECK(buf.ptr != NULL && buf.len == 9 && memcmp(buf.ptr, "data: 1\n\n", 9) == 0);
    strata_buf_free(&buf);
    CHECK(strata_tx_response_body_flush(tx, &buf) == STRATA_OK);
    CHECK(buf.ptr != NULL && buf.len == 0);
    strata_buf_free(&buf);
    CHECK(strata_tx_response_body_chunk(tx, NULL, 0, 1, &buf) == STRATA_OK);
    CHECK(buf.ptr != NULL && buf.len == 0);
    strata_buf_free(&buf);
    CHECK(strata_tx_response_body_flush(tx, NULL) == STRATA_E_INVALID);
    strata_tx_free(tx);
#endif

    /* body over the connector's limit: example-api blocks oversize */
    tx = start(e, 0, S("/upload"));
    strata_tx_free(tx);
    {
        strata_conn_t conn;

        memset(&conn, 0, sizeof(conn));
        conn.node_id = S("web-01");
        tx = strata_tx_new(e, S("example-api"), &conn, 2000);
        CHECK(strata_tx_request_line(tx, S("POST"), S("/u"), S("/u"), S(""), S("HTTP/1.1")) == STRATA_OK);
        CHECK(strata_tx_request_headers(tx, NULL, 0) == STRATA_OK);
        CHECK(strata_tx_request_body_skipped(tx, 100) == STRATA_OK);
        CHECK(strata_tx_request_body_chunk(tx, NULL, 0, 1) == STRATA_OK);
        strata_tx_verdict(tx, &v);
        CHECK(v.action == STRATA_ACTION_BLOCK && v.n_rules == 1 && v.rules[0] == 100020);
        strata_tx_free(tx);

        tx = strata_tx_new(e, S("example-web"), &conn, 2000);
        strata_tx_request_line(tx, S("POST"), S("/u"), S("/u"), S(""), S("HTTP/1.1"));
        strata_tx_request_headers(tx, NULL, 0);
        CHECK(strata_tx_request_body_skipped(tx, 100) == STRATA_OK);
        strata_tx_request_body_chunk(tx, NULL, 0, 1);
        strata_tx_verdict(tx, &v);
        CHECK(v.action == STRATA_ACTION_ALLOW && v.rules[0] == 100020 && v.error == STRATA_OK);
        strata_tx_free(tx);

        /* response layer of the policy: status recorded, CCCD masked */
        tx = strata_tx_new(e, S("example-guard"), &conn, 2000);
        strata_tx_request_line(tx, S("GET"), S("/u"), S("/u"), S(""), S("HTTP/1.1"));
        strata_tx_request_headers(tx, NULL, 0);
        strata_tx_request_body_chunk(tx, NULL, 0, 1);
        strata_tx_verdict(tx, &v);
        CHECK(v.flags & STRATA_VF_NEED_RESPONSE);
        CHECK(strata_tx_response_headers(tx, 500, NULL, 0) == STRATA_OK);
        CHECK(strata_tx_response_body_chunk(tx, (const uint8_t *) "{\"id\":\"001203012345\"}",
                                            21, 1, &buf) == STRATA_OK);
        CHECK(buf.len == 21 && memcmp(buf.ptr, "{\"id\":\"************\"}", 21) == 0);
        strata_buf_free(&buf);
        strata_tx_verdict(tx, &v);
        CHECK(v.action == STRATA_ACTION_ALLOW && v.n_rules == 2);
        CHECK(v.rules[0] == 600001 && v.rules[1] == 600201 && id_ok(v.block_id, "EVT-"));
        strata_tx_free(tx);
    }

    /* the connector reports input it could not pass */
    tx = start(e, 0, S("/"));
    CHECK(strata_tx_fail(tx, STRATA_E_INCOMPLETE) == STRATA_E_INCOMPLETE);
    CHECK(strata_tx_request_body_chunk(tx, NULL, 0, 1) == STRATA_E_INCOMPLETE);
    strata_tx_verdict(tx, &v);
    CHECK(v.error == STRATA_E_INCOMPLETE && id_ok(v.block_id, "EVT-"));
    CHECK(strata_tx_fail(tx, STRATA_OK) == STRATA_E_INVALID);
    CHECK(strata_tx_fail(NULL, STRATA_E_INCOMPLETE) == STRATA_E_INVALID);
    strata_tx_free(tx);

    /* transactions keep the engine alive after the module drops its ref */
    tx = start(e, 0, S("/"));
    strata_engine_release(e);
    CHECK(strata_tx_request_body_chunk(tx, NULL, 0, 1) == STRATA_OK);
    strata_tx_free(tx);

    free(bundle);

    if (failures) {
        fprintf(stderr, "abi_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("abi_test: ok\n");
    return 0;
}
