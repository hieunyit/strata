/*
 * PoC: can a deserialized Hyperscan database be used directly from a
 * read-only shared mapping (mmap PROT_READ, MAP_SHARED) placed at different
 * addresses in different processes?
 *
 *   hs_mmap_poc compile <dir> <npatterns>   build db.ser, db.img, corpus
 *   hs_mmap_poc check   <dir> <nprocs>      scan from the mapping at a
 *                                           different address per process,
 *                                           compare with a private copy
 *   hs_mmap_poc bench   <dir> <nprocs> <none|private|shared>
 *                                           memory per worker (RSS/PSS)
 *   hs_mmap_poc robust  <dir>               tampered header / bytecode:
 *                                           error code or crash?
 *   hs_mmap_poc platform <dir> <npatterns>  native vs generic target:
 *                                           size and scan throughput
 *
 * db.img is the in-memory form produced by hs_deserialize_database_at()
 * into a page-aligned buffer, i.e. what a 4 KB-aligned bundle section would
 * contain. The scan runs in both block and streaming mode databases.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <hs/hs.h>

#define CORPUS_SIZE  (4 * 1024 * 1024)
#define CHUNK        8192            /* streaming chunk, as in the design */

static void
die(const char *what)
{
    fprintf(stderr, "error: %s: %s\n", what, errno ? strerror(errno) : "-");
    exit(1);
}

static double
now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void
path(char *buf, size_t n, const char *dir, const char *name)
{
    if ((size_t) snprintf(buf, n, "%s/%s", dir, name) >= n) {
        errno = ENAMETOOLONG;
        die(name);
    }
}

static void
write_file(const char *dir, const char *name, const void *p, size_t len)
{
    char   fn[4096];
    FILE  *f;

    path(fn, sizeof(fn), dir, name);
    f = fopen(fn, "wb");
    if (f == NULL || fwrite(p, 1, len, f) != len || fclose(f) != 0) {
        die(fn);
    }
}

static void *
read_file(const char *dir, const char *name, size_t *len)
{
    char         fn[4096];
    void        *p;
    FILE        *f;
    struct stat  st;

    path(fn, sizeof(fn), dir, name);
    f = fopen(fn, "rb");
    if (f == NULL || fstat(fileno(f), &st) != 0) {
        die(fn);
    }
    p = malloc(st.st_size);
    if (p == NULL || fread(p, 1, st.st_size, f) != (size_t) st.st_size) {
        die(fn);
    }
    fclose(f);
    *len = st.st_size;
    return p;
}

/* deterministic xorshift so every run builds the same patterns/corpus */
static uint64_t rng = 0x9e3779b97f4a7c15ULL;

static uint32_t
rnd(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return (uint32_t) (rng >> 32);
}

static const char *words[] = {
    "select", "union", "insert", "update", "delete", "script", "iframe",
    "onerror", "onload", "eval", "exec", "system", "passwd", "shadow",
    "cmd", "powershell", "wget", "curl", "base64", "document", "cookie",
    "window", "location", "alert", "prompt", "concat", "char", "sleep",
    "benchmark", "waitfor", "xp_cmdshell", "information_schema",
};
#define NWORDS (sizeof(words) / sizeof(words[0]))

/* CRS-like mix: case-insensitive alternations, classes, bounded repeats */
static char *
make_pattern(unsigned i)
{
    char        *p = malloc(256);
    const char  *a = words[rnd() % NWORDS], *b = words[rnd() % NWORDS];

    if (p == NULL) {
        die("malloc");
    }

    switch (i % 6) {
    case 0:
        snprintf(p, 256, "(?i)%s\\s+%s\\s*\\(\\s*%u", a, b, i);
        break;
    case 1:
        snprintf(p, 256, "(?i)<\\s*%s[^>]{0,40}%s%u", a, b, i);
        break;
    case 2:
        snprintf(p, 256, "%s[0-9a-f]{4,16}%s_%u", a, b, i);
        break;
    case 3:
        snprintf(p, 256, "(?i)(%s|%s)[=:]\\s*['\"][^'\"]{1,32}%u", a, b, i);
        break;
    case 4:
        snprintf(p, 256, "rule-%05u-%s", i, a);
        break;
    default:
        snprintf(p, 256, "(?s)%s.{0,64}%s.{0,8}#%u", a, b, i);
        break;
    }
    return p;
}

static void
make_corpus(unsigned npatterns, unsigned char *buf, size_t len)
{
    char      **lits;
    size_t      i, n;
    unsigned    k, nlits = 0;

    /* regenerate the patterns to plant the literal ones (i % 6 == 4) */
    rng = 0x9e3779b97f4a7c15ULL;
    lits = calloc(npatterns, sizeof(char *));
    if (lits == NULL) {
        die("calloc");
    }
    for (k = 0; k < npatterns; k++) {
        char *p = make_pattern(k);
        if (k % 6 == 4) {
            lits[nlits++] = p;
        } else {
            free(p);
        }
    }

    for (i = 0; i < len; i++) {
        buf[i] = " etaoinshrdlucmfwypvbgkqjxz=&?/<>()'\"0123456789"[rnd() % 47];
    }

    for (k = 0; k < 2000 && nlits; k++) {
        const char *lit = lits[rnd() % nlits];
        n = strlen(lit);
        i = rnd() % (len - n);
        memcpy(buf + i, lit, n);
    }

    for (k = 0; k < nlits; k++) {
        free(lits[k]);
    }
    free(lits);
}

static int
on_match(unsigned id, unsigned long long from, unsigned long long to,
         unsigned flags, void *ctx)
{
    (void) id; (void) from; (void) to; (void) flags;
    (*(uint64_t *) ctx)++;
    return 0;
}

static hs_database_t *
compile(unsigned n, unsigned mode)
{
    unsigned             i;
    char               **pats;
    unsigned            *ids, *flags;
    hs_database_t       *db;
    hs_compile_error_t  *err;

    rng = 0x9e3779b97f4a7c15ULL;
    pats = calloc(n, sizeof(char *));
    ids = calloc(n, sizeof(unsigned));
    flags = calloc(n, sizeof(unsigned));
    if (pats == NULL || ids == NULL || flags == NULL) {
        die("calloc");
    }

    for (i = 0; i < n; i++) {
        pats[i] = make_pattern(i);
        ids[i] = i;
        flags[i] = HS_FLAG_SINGLEMATCH;
    }

    if (hs_compile_multi((const char *const *) pats, flags, ids, n, mode, NULL,
                         &db, &err)
        != HS_SUCCESS)
    {
        fprintf(stderr, "compile failed at %d: %s\n", err->expression, err->message);
        exit(1);
    }

    for (i = 0; i < n; i++) {
        free(pats[i]);
    }
    free(pats);
    free(ids);
    free(flags);
    return db;
}

/* deserialize into a page-aligned buffer: the bundle section image */
static void
save(const char *dir, const char *tag, hs_database_t *db)
{
    char    *ser, name[64];
    void    *img;
    size_t   ser_len, img_len;

    if (hs_serialize_database(db, &ser, &ser_len) != HS_SUCCESS
        || hs_serialized_database_size(ser, ser_len, &img_len) != HS_SUCCESS)
    {
        die("serialize");
    }

    if (posix_memalign(&img, 4096, img_len) != 0) {
        die("posix_memalign");
    }
    memset(img, 0, img_len);

    if (hs_deserialize_database_at(ser, ser_len, (hs_database_t *) img) != HS_SUCCESS) {
        die("deserialize_at");
    }

    snprintf(name, sizeof(name), "%s.ser", tag);
    write_file(dir, name, ser, ser_len);
    snprintf(name, sizeof(name), "%s.img", tag);
    write_file(dir, name, img, img_len);

    printf("%s: serialized %zu bytes, in-memory image %zu bytes\n", tag, ser_len, img_len);
    free(ser);
    free(img);
}

static uint64_t
scan_block(const hs_database_t *db, hs_scratch_t *s, const unsigned char *c, size_t len)
{
    uint64_t  hits = 0;

    if (hs_scan(db, (const char *) c, len, 0, s, on_match, &hits) != HS_SUCCESS) {
        die("hs_scan");
    }
    return hits;
}

static uint64_t
scan_stream(const hs_database_t *db, hs_scratch_t *s, const unsigned char *c, size_t len)
{
    size_t        off;
    uint64_t      hits = 0;
    hs_stream_t  *st;

    if (hs_open_stream(db, 0, &st) != HS_SUCCESS) {
        die("hs_open_stream");
    }
    for (off = 0; off < len; off += CHUNK) {
        size_t n = len - off < CHUNK ? len - off : CHUNK;
        if (hs_scan_stream(st, (const char *) c + off, n, 0, s, on_match, &hits)
            != HS_SUCCESS)
        {
            die("hs_scan_stream");
        }
    }
    if (hs_close_stream(st, s, on_match, &hits) != HS_SUCCESS) {
        die("hs_close_stream");
    }
    return hits;
}

/* read every page so RSS/PSS reflect the whole database (worst case) */
static void
touch(const void *p, size_t len)
{
    size_t                  i;
    volatile unsigned char  sink = 0;

    for (i = 0; i < len; i += 4096) {
        sink ^= ((const unsigned char *) p)[i];
    }
    (void) sink;
}

/* map db.img read-only at a process-specific address */
static const hs_database_t *
map_image(const char *dir, const char *tag, unsigned slot, size_t *len)
{
    int          fd;
    char         fn[4096], name[64];
    void        *hint, *p;
    struct stat  st;

    snprintf(name, sizeof(name), "%s.img", tag);
    path(fn, sizeof(fn), dir, name);
    fd = open(fn, O_RDONLY);
    if (fd < 0 || fstat(fd, &st) != 0) {
        die(fn);
    }

    /* distinct, page-aligned (not 64 KB-aligned) hint per process and db */
    hint = (void *) (uintptr_t) (0x6f0000000000ULL + slot * 0x100000000ULL
                                 + (tag[0] == 's') * 0x40000000ULL
                                 + slot * 7 * 4096ULL);
    p = mmap(hint, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        die("mmap");
    }
    close(fd);
    madvise(p, st.st_size, MADV_WILLNEED);
    touch(p, st.st_size);
    *len = st.st_size;
    return p;
}

/* sums Rss/Pss/Private_Dirty over [lo, hi) mappings, or the whole process */
static void
smaps_range(uintptr_t lo, uintptr_t hi, unsigned long long v[3])
{
    char                line[512];
    FILE               *f;
    int                 in = 0;
    unsigned long long  a, b;

    v[0] = v[1] = v[2] = 0;
    f = fopen("/proc/self/smaps", "r");
    if (f == NULL) {
        die("smaps");
    }
    while (fgets(line, sizeof(line), f)) {
        /* mapping header: "<start>-<end> perms offset dev inode path" */
        if (sscanf(line, "%llx-%llx", &a, &b) == 2 && line[strspn(line, "0123456789abcdef")] == '-') {
            in = (lo == 0 && hi == 0) || (a >= lo && a < hi);
            continue;
        }
        if (!in) {
            continue;
        }
        if (strncmp(line, "Rss:", 4) == 0) v[0] += strtoull(line + 4, NULL, 10);
        else if (strncmp(line, "Pss:", 4) == 0) v[1] += strtoull(line + 4, NULL, 10);
        else if (strncmp(line, "Private_Dirty:", 14) == 0) v[2] += strtoull(line + 14, NULL, 10);
    }
    fclose(f);
}

static void
report(const char *mode, unsigned slot, const void *b, size_t blen,
       const void *st, size_t slen, double load_ms)
{
    unsigned long long  all[3], db1[3], db2[3];

    smaps_range(0, 0, all);
    printf("%s worker=%u load_ms=%.2f proc_rss_kb=%llu proc_pss_kb=%llu proc_private_dirty_kb=%llu",
           mode, slot, load_ms, all[0], all[1], all[2]);
    if (strcmp(mode, "shared") == 0) {
        smaps_range((uintptr_t) b, (uintptr_t) b + blen, db1);
        smaps_range((uintptr_t) st, (uintptr_t) st + slen, db2);
        printf(" db_rss_kb=%llu db_pss_kb=%llu", db1[0] + db2[0], db1[1] + db2[1]);
    }
    printf("\n");
    fflush(stdout);
}

static int
cmd_compile(const char *dir, unsigned n)
{
    double          t;
    unsigned char  *corpus;
    hs_database_t  *block, *stream;

    t = now();
    block = compile(n, HS_MODE_BLOCK);
    printf("compiled %u patterns (block) in %.1f s\n", n, now() - t);
    t = now();
    stream = compile(n, HS_MODE_STREAM | HS_MODE_SOM_HORIZON_SMALL);
    printf("compiled %u patterns (stream) in %.1f s\n", n, now() - t);

    save(dir, "block", block);
    save(dir, "stream", stream);

    corpus = malloc(CORPUS_SIZE);
    if (corpus == NULL) {
        die("malloc");
    }
    make_corpus(n, corpus, CORPUS_SIZE);
    write_file(dir, "corpus", corpus, CORPUS_SIZE);

    hs_free_database(block);
    hs_free_database(stream);
    free(corpus);
    return 0;
}

/* expected results from private, freshly deserialized copies */
static void
expected(const char *dir, const unsigned char *c, size_t len, uint64_t *eb, uint64_t *es)
{
    char           *ser;
    size_t          n;
    hs_scratch_t   *s = NULL;
    hs_database_t  *b, *st;

    ser = read_file(dir, "block.ser", &n);
    if (hs_deserialize_database(ser, n, &b) != HS_SUCCESS) die("deserialize");
    free(ser);
    ser = read_file(dir, "stream.ser", &n);
    if (hs_deserialize_database(ser, n, &st) != HS_SUCCESS) die("deserialize");
    free(ser);
    if (hs_alloc_scratch(b, &s) != HS_SUCCESS || hs_alloc_scratch(st, &s) != HS_SUCCESS) {
        die("scratch");
    }
    *eb = scan_block(b, s, c, len);
    *es = scan_stream(st, s, c, len);
    hs_free_scratch(s);
    hs_free_database(b);
    hs_free_database(st);
}

static int
cmd_check(const char *dir, unsigned nprocs)
{
    int             status, failed = 0;
    size_t          clen, blen, slen;
    pid_t           pid;
    uint64_t        eb, es;
    unsigned        i;
    unsigned char  *corpus;

    corpus = read_file(dir, "corpus", &clen);
    expected(dir, corpus, clen, &eb, &es);
    printf("expected: block=%" PRIu64 " stream=%" PRIu64 " matches\n", eb, es);

    fflush(stdout);

    for (i = 0; i < nprocs; i++) {
        pid = fork();
        if (pid < 0) {
            die("fork");
        }
        if (pid == 0) {
            const hs_database_t *b = map_image(dir, "block", i + 1, &blen);
            const hs_database_t *st = map_image(dir, "stream", i + 1, &slen);
            hs_scratch_t        *s = NULL;
            char                *info;
            uint64_t             hb, hs;

            if (hs_database_info(b, &info) != HS_SUCCESS) die("database_info");
            if (i == 0) printf("database: %s\n", info);
            free(info);
            if (hs_alloc_scratch(b, &s) != HS_SUCCESS || hs_alloc_scratch(st, &s) != HS_SUCCESS) {
                die("scratch");
            }
            hb = scan_block(b, s, corpus, clen);
            hs = scan_stream(st, s, corpus, clen);
            printf("proc %u: block db at %p -> %" PRIu64 ", stream db at %p -> %" PRIu64 " %s\n",
                   i, (const void *) b, hb, (const void *) st, hs,
                   hb == eb && hs == es ? "OK" : "MISMATCH");
            fflush(stdout);
            _exit(hb == eb && hs == es ? 0 : 2);
        }
    }

    for (i = 0; i < nprocs; i++) {
        if (wait(&status) < 0) die("wait");
        if (WIFSIGNALED(status)) {
            printf("child killed by signal %d\n", WTERMSIG(status));
            failed = 1;
        } else if (WEXITSTATUS(status) != 0) {
            failed = 1;
        }
    }
    printf("check: %s\n", failed ? "FAILED" : "all processes matched");
    free(corpus);
    return failed;
}

static int
cmd_bench(const char *dir, unsigned nprocs, const char *mode)
{
    int             ready[2], go[2], done[2], status;
    char            c;
    size_t          clen, n;
    unsigned        i;
    unsigned char  *corpus;

    corpus = read_file(dir, "corpus", &clen);
    if (pipe(ready) != 0 || pipe(go) != 0 || pipe(done) != 0) die("pipe");
    fflush(stdout);

    for (i = 0; i < nprocs; i++) {
        pid_t pid = fork();
        if (pid < 0) die("fork");
        if (pid == 0) {
            const hs_database_t *b = NULL, *st = NULL;
            hs_database_t       *pb, *pst;
            hs_scratch_t        *s = NULL;
            char                *ser;
            size_t               sz;

            size_t               bsz = 0, ssz = 0;
            double               t = now();

            if (strcmp(mode, "shared") == 0) {
                b = map_image(dir, "block", i + 1, &bsz);
                st = map_image(dir, "stream", i + 1, &ssz);
            } else if (strcmp(mode, "private") == 0) {
                ser = read_file(dir, "block.ser", &sz);
                if (hs_deserialize_database(ser, sz, &pb) != HS_SUCCESS) die("deser");
                free(ser);
                ser = read_file(dir, "stream.ser", &sz);
                if (hs_deserialize_database(ser, sz, &pst) != HS_SUCCESS) die("deser");
                free(ser);
                b = pb;
                st = pst;
            }
            t = (now() - t) * 1000;
            if (b != NULL) {
                if (hs_alloc_scratch(b, &s) != HS_SUCCESS
                    || hs_alloc_scratch(st, &s) != HS_SUCCESS)
                {
                    die("scratch");
                }
                scan_block(b, s, corpus, clen);   /* touch every page */
                scan_stream(st, s, corpus, clen);
                if (i == 0) {
                    hs_scratch_size(s, &n);
                    printf("%s scratch per worker: %zu bytes\n", mode, n);
                }
            }
            /* barrier: measure while every worker is alive */
            if (write(ready[1], "r", 1) != 1 || read(go[0], &c, 1) != 1) die("barrier");
            report(mode, i, b, bsz, st, ssz, t);
            if (write(ready[1], "m", 1) != 1 || read(done[0], &c, 1) != 1) die("barrier");
            _exit(0);
        }
    }

    for (i = 0; i < nprocs; i++) {
        if (read(ready[0], &c, 1) != 1) die("barrier");
    }
    for (i = 0; i < nprocs; i++) {
        if (write(go[1], "g", 1) != 1) die("barrier");
    }
    for (i = 0; i < nprocs; i++) {   /* every worker has measured */
        if (read(ready[0], &c, 1) != 1) die("barrier");
    }
    for (i = 0; i < nprocs; i++) {
        if (write(done[1], "x", 1) != 1) die("barrier");
    }
    for (i = 0; i < nprocs; i++) {
        if (wait(&status) < 0) die("wait");
    }
    free(corpus);
    return 0;
}

/*
 * Runs one scan in a child so a crash is observed, not suffered. Scratch is
 * allocated for `scratch_db` (which validates its CRC), then `db` is scanned:
 * passing an intact database there models corruption after load.
 */
static const char *
scan_in_child2(const hs_database_t *scratch_db, const hs_database_t *db,
               const unsigned char *c, size_t len)
{
    int     status;
    pid_t   pid;

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        die("fork");
    }
    if (pid == 0) {
        hs_scratch_t  *s = NULL;
        uint64_t       hits = 0;
        hs_error_t     rc;

        rc = hs_alloc_scratch(scratch_db, &s);
        if (rc != HS_SUCCESS) {
            _exit(100 + (-rc));
        }
        rc = hs_scan(db, (const char *) c, len, 0, s, on_match, &hits);
        _exit(rc == HS_SUCCESS ? 0 : 100 + (-rc));
    }
    if (waitpid(pid, &status, 0) < 0) {
        die("waitpid");
    }
    if (WIFSIGNALED(status)) {
        static char buf[64];
        snprintf(buf, sizeof(buf), "CRASH (signal %d)", WTERMSIG(status));
        return buf;
    }
    switch (WEXITSTATUS(status)) {
    case 0:   return "scan ok";
    case 101: return "HS_INVALID";
    case 102: return "HS_NOMEM";
    case 105: return "HS_DB_VERSION_ERROR";
    case 106: return "HS_DB_PLATFORM_ERROR";
    case 107: return "HS_DB_MODE_ERROR";
    case 108: return "HS_BAD_ALIGN";
    default: {
        static char buf[64];
        snprintf(buf, sizeof(buf), "error %d", 100 - WEXITSTATUS(status));
        return buf;
    }
    }
}

static const char *
scan_in_child(const hs_database_t *db, const unsigned char *c, size_t len)
{
    return scan_in_child2(db, db, c, len);
}

static int
cmd_robust(const char *dir)
{
    int             trial, crashes = 0, errors = 0, oks = 0;
    char           *img;
    void           *buf;
    size_t          len, clen, off;
    uint32_t        u32;
    uint64_t        u64;
    unsigned char  *corpus;

    img = read_file(dir, "block.img", &len);
    corpus = read_file(dir, "corpus", &clen);
    if (posix_memalign(&buf, 4096, len) != 0) {
        die("posix_memalign");
    }

    /* header layout of Hyperscan 5.x: magic, version, length, platform... */
    memcpy(&u32, img, 4);
    printf("header: magic=0x%08x", u32);
    memcpy(&u32, img + 4, 4);
    printf(" version=0x%08x", u32);
    memcpy(&u32, img + 8, 4);
    printf(" length=%u", u32);
    memcpy(&u64, img + 16, 8);
    printf(" platform=0x%016" PRIx64 "\n", u64);

    memcpy(buf, img, len);
    printf("%-40s %s\n", "intact copy", scan_in_child(buf, corpus, clen));

    memcpy(buf, img, len);
    ((unsigned char *) buf)[0] ^= 0xff;
    printf("%-40s %s\n", "magic changed", scan_in_child(buf, corpus, clen));

    memcpy(buf, img, len);
    ((unsigned char *) buf)[5] ^= 0x01;          /* minor version */
    printf("%-40s %s\n", "version changed", scan_in_child(buf, corpus, clen));

    memcpy(buf, img, len);
    u64 = ~(uint64_t) 0;
    memcpy((char *) buf + 16, &u64, 8);
    printf("%-40s %s\n", "platform set to all features", scan_in_child(buf, corpus, clen));

    /* bytecode corruption: the CRC is only checked by hs_deserialize_*() */
    rng = 0x1234567;
    for (trial = 0; trial < 200; trial++) {
        const char *r;
        int         k;

        memcpy(buf, img, len);
        for (k = 0; k < 16; k++) {
            off = 4096 + rnd() % (len - 4096);
            ((unsigned char *) buf)[off] = (unsigned char) rnd();
        }
        r = scan_in_child(buf, corpus, clen);
        if (strncmp(r, "CRASH", 5) == 0) {
            crashes++;
        } else if (strcmp(r, "scan ok") == 0) {
            oks++;
        } else {
            if (errors++ == 0) {
                printf("%-40s first error: %s\n", "", r);
            }
        }
    }
    printf("%-40s %d crash, %d error code, %d scan ok (of 200)\n",
           "16 random bytes of bytecode changed", crashes, errors, oks);

    /* same corruption, but after scratch was allocated on the intact db */
    crashes = errors = oks = 0;
    for (trial = 0; trial < 200; trial++) {
        const char *r;
        int         k;

        memcpy(buf, img, len);
        for (k = 0; k < 16; k++) {
            off = 4096 + rnd() % (len - 4096);
            ((unsigned char *) buf)[off] = (unsigned char) rnd();
        }
        r = scan_in_child2((const hs_database_t *) img, buf, corpus, clen);
        if (strncmp(r, "CRASH", 5) == 0) {
            crashes++;
        } else if (strcmp(r, "scan ok") == 0) {
            oks++;
        } else {
            errors++;
        }
    }
    printf("%-40s %d crash, %d error code, %d scan ok (of 200)\n",
           "same, corrupted after scratch alloc", crashes, errors, oks);

    free(buf);
    free(img);
    free(corpus);
    return 0;
}

static double
throughput(const hs_database_t *db, const unsigned char *c, size_t len)
{
    int            i;
    double         t;
    hs_scratch_t  *s = NULL;

    if (hs_alloc_scratch(db, &s) != HS_SUCCESS) {
        die("scratch");
    }
    scan_block(db, s, c, len);                       /* warm up */
    t = now();
    for (i = 0; i < 10; i++) {
        scan_block(db, s, c, len);
    }
    t = now() - t;
    hs_free_scratch(s);
    return 10.0 * len / t / (1024 * 1024);
}

static int
cmd_platform(const char *dir, unsigned n)
{
    size_t               clen, size;
    unsigned             i;
    char               **pats;
    unsigned            *ids, *flags;
    unsigned char       *corpus;
    hs_database_t       *db[2];
    hs_platform_info_t   native, generic;
    hs_compile_error_t  *err;
    static const char   *names[2] = { "native", "generic" };

    corpus = read_file(dir, "corpus", &clen);

    if (hs_populate_platform(&native) != HS_SUCCESS) {
        die("hs_populate_platform");
    }
    memset(&generic, 0, sizeof(generic));
    generic.tune = HS_TUNE_FAMILY_GENERIC;
    generic.cpu_features = 0;

    rng = 0x9e3779b97f4a7c15ULL;
    pats = calloc(n, sizeof(char *));
    ids = calloc(n, sizeof(unsigned));
    flags = calloc(n, sizeof(unsigned));
    if (pats == NULL || ids == NULL || flags == NULL) {
        die("calloc");
    }
    for (i = 0; i < n; i++) {
        pats[i] = make_pattern(i);
        ids[i] = i;
        flags[i] = HS_FLAG_SINGLEMATCH;
    }

    for (i = 0; i < 2; i++) {
        double t = now();
        if (hs_compile_multi((const char *const *) pats, flags, ids, n, HS_MODE_BLOCK,
                             i == 0 ? &native : &generic, &db[i], &err)
            != HS_SUCCESS)
        {
            fprintf(stderr, "compile failed: %s\n", err->message);
            return 1;
        }
        t = now() - t;
        hs_database_size(db[i], &size);
        printf("%-8s cpu_features=0x%llx compile %.1f s, size %zu bytes, "
               "block scan %.0f MB/s\n",
               names[i], (unsigned long long) (i == 0 ? native.cpu_features : 0),
               t, size, throughput(db[i], corpus, clen));
    }

    for (i = 0; i < n; i++) {
        free(pats[i]);
    }
    free(pats);
    free(ids);
    free(flags);
    hs_free_database(db[0]);
    hs_free_database(db[1]);
    free(corpus);
    return 0;
}

int
main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "compile") == 0) {
        return cmd_compile(argv[2], (unsigned) atoi(argv[3]));
    }
    if (argc == 4 && strcmp(argv[1], "check") == 0) {
        return cmd_check(argv[2], (unsigned) atoi(argv[3]));
    }
    if (argc == 5 && strcmp(argv[1], "bench") == 0) {
        return cmd_bench(argv[2], (unsigned) atoi(argv[3]), argv[4]);
    }
    if (argc == 3 && strcmp(argv[1], "robust") == 0) {
        return cmd_robust(argv[2]);
    }
    if (argc == 4 && strcmp(argv[1], "platform") == 0) {
        return cmd_platform(argv[2], (unsigned) atoi(argv[3]));
    }
    fprintf(stderr, "usage: %s compile <dir> <npatterns> | check <dir> <nprocs> | "
                    "bench <dir> <nprocs> <none|private|shared> | robust <dir> | "
                    "platform <dir> <npatterns>\n", argv[0]);
    return 2;
}
