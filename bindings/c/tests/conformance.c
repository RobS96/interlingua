/*
 * C conformance runner: checks the C ABI against the .rsp files in spec/vectors.
 *
 *   conformance <vectors-dir>
 *
 * Exit 0 when every check passes. Built with -Wall -Wextra -Werror -pedantic
 * and run under AddressSanitizer + UndefinedBehaviorSanitizer by `make c`,
 * which also proves the C side of the boundary handles memory correctly.
 */
#include "interlingua.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *key;
    char *value;
} field;

typedef struct {
    char *section;
    char *name;
    field *fields;
    size_t nfields;
} record;

typedef struct {
    record *items;
    size_t len;
} records;

static int passed = 0;
static int failed = 0;

static void check(int ok, const char *file, const char *what) {
    if (ok) {
        passed++;
    } else {
        failed++;
        fprintf(stderr, "FAIL %s: %s\n", file, what);
    }
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n);
    if (q == NULL) {
        fputs("out of memory\n", stderr);
        exit(70);
    }
    return q;
}

static char *read_file(const char *dir, const char *name, size_t *len_out) {
    char path[4096];
    if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path) {
        fputs("path too long\n", stderr);
        exit(64);
    }
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        exit(66);
    }
    size_t cap = 1 << 16, len = 0;
    char *buf = xrealloc(NULL, cap + 1);
    size_t n;
    while ((n = fread(buf + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            buf = xrealloc(buf, cap + 1);
        }
    }
    fclose(f);
    buf[len] = '\0';
    if (len_out != NULL) {
        *len_out = len;
    }
    return buf;
}

static char *trim(char *s) {
    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return s;
}

/* Parse .rsp text in place (the strings point into `text`). */
static records parse_rsp(char *text) {
    records out = {NULL, 0};
    record cur = {NULL, NULL, NULL, 0};
    char *section = "";
    char *save = NULL;
    for (char *line = text; line != NULL; line = save) {
        char *nl = strchr(line, '\n');
        save = nl != NULL ? nl + 1 : NULL;
        if (nl != NULL) {
            *nl = '\0';
        }
        char *t = trim(line);
        if (*t == '#') {
            continue;
        }
        if (*t == '\0' || *t == '[') {
            if (cur.nfields > 0) {
                out.items = xrealloc(out.items, (out.len + 1) * sizeof(record));
                out.items[out.len++] = cur;
                cur = (record){NULL, NULL, NULL, 0};
            }
            if (*t == '[') {
                char *close = strrchr(t, ']');
                if (close != NULL) {
                    *close = '\0';
                }
                section = trim(t + 1);
            }
            continue;
        }
        char *eq = strchr(t, '=');
        if (eq == NULL) {
            fprintf(stderr, "malformed vector line: %s\n", t);
            exit(65);
        }
        *eq = '\0';
        cur.section = section;
        cur.fields = xrealloc(cur.fields, (cur.nfields + 1) * sizeof(field));
        cur.fields[cur.nfields++] = (field){trim(t), trim(eq + 1)};
    }
    if (cur.nfields > 0) {
        out.items = xrealloc(out.items, (out.len + 1) * sizeof(record));
        out.items[out.len++] = cur;
    }
    for (size_t i = 0; i < out.len; i++) {
        out.items[i].name = "";
        for (size_t j = 0; j < out.items[i].nfields; j++) {
            if (strcmp(out.items[i].fields[j].key, "name") == 0) {
                out.items[i].name = out.items[i].fields[j].value;
            }
        }
    }
    return out;
}

static void free_records(records *r) {
    for (size_t i = 0; i < r->len; i++) {
        free(r->items[i].fields);
    }
    free(r->items);
    r->items = NULL;
    r->len = 0;
}

static const char *get(const record *r, const char *key) {
    for (size_t i = 0; i < r->nfields; i++) {
        if (strcmp(r->fields[i].key, key) == 0) {
            return r->fields[i].value;
        }
    }
    return NULL;
}

static const char *need(const record *r, const char *key) {
    const char *v = get(r, key);
    if (v == NULL) {
        fprintf(stderr, "vector record is missing `%s`\n", key);
        exit(65);
    }
    return v;
}

static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Hex to a malloc'd buffer (never NULL; length in *len). */
static uint8_t *unhex(const char *hex, size_t *len) {
    size_t n = strlen(hex);
    if (n % 2 != 0) {
        fprintf(stderr, "odd-length hex\n");
        exit(65);
    }
    uint8_t *out = xrealloc(NULL, n / 2 + 1);
    for (size_t i = 0; i < n / 2; i++) {
        int hi = nibble(hex[2 * i]), lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "bad hex\n");
            exit(65);
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *len = n / 2;
    return out;
}

static int buf_is(const il_buf *b, const uint8_t *data, size_t len) {
    if (b->len != len) return 0;
    return len == 0 || memcmp(b->ptr, data, len) == 0;
}

static int buf_is_text(const il_buf *b, const char *text) {
    return buf_is(b, (const uint8_t *)text, strlen(text));
}

/* The last error id as a NUL-terminated string in `out`. */
static void last_error(char *out, size_t cap) {
    il_buf b = {NULL, 0};
    out[0] = '\0';
    if (il_last_error_id(&b) == IL_OK && b.len < cap) {
        if (b.len > 0) memcpy(out, b.ptr, b.len);
        out[b.len] = '\0';
    }
    il_buf_free(&b);
}

static void check_cbor(const char *dir) {
    char *text = read_file(dir, "cbor.rsp", NULL);
    records rs = parse_rsp(text);
    for (size_t i = 0; i < rs.len; i++) {
        const record *r = &rs.items[i];
        size_t n;
        uint8_t *input = unhex(need(r, "cbor"), &n);
        il_buf out = {NULL, 0};
        int rc = il_cbor_canonical(input, n, &out);
        if (strcmp(need(r, "expect"), "accept") == 0) {
            check(rc == IL_OK && buf_is(&out, input, n), "cbor.rsp", need(r, "cbor"));
            const char *diag = get(r, "diag");
            if (diag != NULL) {
                il_buf d = {NULL, 0};
                check(il_cbor_diag(input, n, &d) == IL_OK && buf_is_text(&d, diag), "cbor.rsp diag", diag);
                il_buf_free(&d);
            }
        } else {
            char id[128];
            last_error(id, sizeof id);
            check(rc != IL_OK && strcmp(id, need(r, "error")) == 0, "cbor.rsp reject", need(r, "cbor"));
        }
        il_buf_free(&out);
        free(input);
    }
    free_records(&rs);
    free(text);
}

static void check_label(const char *dir) {
    char *text = read_file(dir, "label.rsp", NULL);
    records rs = parse_rsp(text);
    for (size_t i = 0; i < rs.len; i++) {
        const record *r = &rs.items[i];
        il_buf canon = {NULL, 0}, cbor = {NULL, 0};
        int rc = il_label_normalize(need(r, "text"), &canon, &cbor);
        if (strcmp(need(r, "expect"), "accept") == 0) {
            size_t n;
            uint8_t *want = unhex(need(r, "cbor"), &n);
            check(rc == IL_OK && buf_is_text(&canon, need(r, "canonical")) && buf_is(&cbor, want, n), "label.rsp", need(r, "text"));
            free(want);
        } else {
            char id[128];
            last_error(id, sizeof id);
            check(rc != IL_OK && strcmp(id, need(r, "error")) == 0, "label.rsp reject", need(r, "text"));
        }
        il_buf_free(&canon);
        il_buf_free(&cbor);
    }
    free_records(&rs);
    free(text);
}

static void check_ccsds(const char *dir) {
    static const char *const flag_names[4] = {"continuation", "first", "last", "unsegmented"};
    char *text = read_file(dir, "ccsds.rsp", NULL);
    records rs = parse_rsp(text);
    for (size_t i = 0; i < rs.len; i++) {
        const record *r = &rs.items[i];
        size_t plen;
        uint8_t *packet = unhex(need(r, "packet"), &plen);
        uint8_t tc = 0, sec = 0, flags = 0;
        uint16_t apid = 0, count = 0;
        size_t used = 0;
        il_buf data = {NULL, 0};
        int rc = il_ccsds_packet_decode(packet, plen, &tc, &sec, &apid, &flags, &count, &used, &data);
        if (strcmp(need(r, "expect"), "accept") == 0) {
            size_t dlen;
            uint8_t *want = unhex(need(r, "data"), &dlen);
            uint8_t want_flags = 0;
            for (uint8_t f = 0; f < 4; f++) {
                if (strcmp(need(r, "flags"), flag_names[f]) == 0) want_flags = f;
            }
            uint8_t want_tc = strcmp(need(r, "type"), "tc") == 0;
            uint8_t want_sec = strcmp(need(r, "sec"), "1") == 0;
            uint16_t want_apid = (uint16_t)strtoul(need(r, "apid"), NULL, 10);
            uint16_t want_count = (uint16_t)strtoul(need(r, "count"), NULL, 10);
            check(rc == IL_OK && tc == want_tc && sec == want_sec && apid == want_apid && flags == want_flags &&
                      count == want_count && used == plen && buf_is(&data, want, dlen),
                  "ccsds.rsp decode", need(r, "packet"));
            il_buf enc = {NULL, 0};
            int erc = il_ccsds_packet_encode(want_tc, want_sec, want_apid, want_flags, want_count, want, dlen, &enc);
            check(erc == IL_OK && buf_is(&enc, packet, plen), "ccsds.rsp encode", need(r, "packet"));
            il_buf_free(&enc);
            free(want);
        } else {
            char id[128];
            last_error(id, sizeof id);
            check(rc != IL_OK && strcmp(id, need(r, "error")) == 0, "ccsds.rsp reject", need(r, "packet"));
        }
        il_buf_free(&data);
        free(packet);
    }
    free_records(&rs);
    free(text);
}

/* The secret bundle for `domain` inside test-secrets.txt (a pointer range). */
static const char *find_secret(const char *secrets, const char *domain, size_t *len) {
    const char *magic = "interlingua-secret-key v1\n";
    for (const char *p = strstr(secrets, magic); p != NULL; p = strstr(p + 1, magic)) {
        const char *d = p + strlen(magic);
        size_t dl = strlen(domain);
        if (strncmp(d, "domain ", 7) == 0 && strncmp(d + 7, domain, dl) == 0 && d[7 + dl] == '\n') {
            const char *next = strstr(p + 1, magic);
            *len = next != NULL ? (size_t)(next - p) : strlen(p);
            return p;
        }
    }
    fprintf(stderr, "no test key for %s\n", domain);
    exit(65);
}

static void check_envelope(const char *dir) {
    size_t ring_len, sec_len;
    char *ring = read_file(dir, "keyring.pub", &ring_len);
    char *secrets = read_file(dir, "test-secrets.txt", &sec_len);
    char *text = read_file(dir, "envelope.rsp", NULL);
    records rs = parse_rsp(text);
    for (size_t i = 0; i < rs.len; i++) {
        const record *r = &rs.items[i];
        size_t elen, klen = 0;
        uint8_t *env = unhex(need(r, "envelope"), &elen);
        const char *key = NULL;
        if (get(r, "recipient") != NULL) {
            key = find_secret(secrets, get(r, "recipient"), &klen);
        }
        il_buf payload = {NULL, 0};
        int rc = il_open((const uint8_t *)key, klen, (const uint8_t *)ring, ring_len, env, elen, &payload);
        const char *expect = need(r, "expect");
        if (strcmp(expect, "valid") == 0) {
            size_t plen;
            uint8_t *want = unhex(need(r, "payload"), &plen);
            check(rc == IL_OK && buf_is(&payload, want, plen), "envelope.rsp", r->name);
            free(want);
        } else {
            char id[128];
            last_error(id, sizeof id);
            check(rc != IL_OK && strncmp(expect, "error:", 6) == 0 && strcmp(id, expect + 6) == 0, "envelope.rsp", r->name);
        }
        il_buf_free(&payload);
        free(env);
    }
    free_records(&rs);
    free(text);
    free(secrets);
    free(ring);
}

/* Value of ` key=` in an audit line, copied into `out`. */
static void audit_field(const il_buf *line, const char *key, char *out, size_t cap) {
    out[0] = '\0';
    char pattern[64];
    snprintf(pattern, sizeof pattern, " %s=", key);
    size_t pl = strlen(pattern);
    for (size_t i = 0; i + pl <= line->len; i++) {
        if (memcmp(line->ptr + i, pattern, pl) == 0) {
            size_t start = i + pl, end = start;
            while (end < line->len && line->ptr[end] != ' ') end++;
            size_t n = end - start < cap - 1 ? end - start : cap - 1;
            memcpy(out, line->ptr + start, n);
            out[n] = '\0';
            return;
        }
    }
}

#define MAX_ROUTERS 16

static void check_routing(const char *dir) {
    size_t ring_len;
    char *ring = read_file(dir, "keyring.pub", &ring_len);
    char *policy = read_file(dir, "routing-policy.ndb", NULL);
    char *text = read_file(dir, "routing.rsp", NULL);
    records rs = parse_rsp(text);
    struct {
        const char *node;
        il_router *router;
    } routers[MAX_ROUTERS];
    size_t nrouters = 0;
    const char *section = NULL;
    il_buf forwarded = {NULL, 0};
    for (size_t i = 0; i < rs.len; i++) {
        const record *r = &rs.items[i];
        if (section == NULL || strcmp(section, r->section) != 0) {
            for (size_t j = 0; j < nrouters; j++) il_router_free(routers[j].router);
            nrouters = 0;
            il_buf_free(&forwarded);
            section = r->section;
        }
        const char *node = need(r, "node");
        il_router *router = NULL;
        for (size_t j = 0; j < nrouters; j++) {
            if (strcmp(routers[j].node, node) == 0) router = routers[j].router;
        }
        if (router == NULL) {
            if (nrouters == MAX_ROUTERS || il_router_new(policy, (const uint8_t *)ring, ring_len, node, &router) != IL_OK) {
                fprintf(stderr, "cannot create a router for %s\n", node);
                exit(70);
            }
            routers[nrouters].node = node;
            routers[nrouters].router = router;
            nrouters++;
        }
        const char *from = strcmp(need(r, "from"), "-") == 0 ? NULL : need(r, "from");
        uint64_t now = strtoull(need(r, "now"), NULL, 10);
        size_t elen = 0;
        uint8_t *env = NULL;
        if (strcmp(need(r, "envelope"), "forwarded") == 0) {
            elen = forwarded.len;
            env = xrealloc(NULL, elen + 1);
            if (elen > 0) memcpy(env, forwarded.ptr, elen);
        } else {
            env = unhex(need(r, "envelope"), &elen);
        }
        il_buf decision = {NULL, 0}, onward = {NULL, 0};
        int rc = il_router_route(router, env, elen, from, now, &decision, &onward);
        char verdict[32], next[80], reason[64], got[160];
        audit_field(&decision, "verdict", verdict, sizeof verdict);
        audit_field(&decision, "next", next, sizeof next);
        audit_field(&decision, "reason", reason, sizeof reason);
        if (strcmp(verdict, "forward") == 0) {
            snprintf(got, sizeof got, "forward:%s", next);
        } else if (strcmp(verdict, "reject") == 0) {
            snprintf(got, sizeof got, "reject:%s", reason);
        } else {
            snprintf(got, sizeof got, "%s", verdict);
        }
        char what[256];
        snprintf(what, sizeof what, "[%s] %s: wanted %s, got %s", r->section, r->name, need(r, "expect"), got);
        check(rc == IL_OK && strcmp(got, need(r, "expect")) == 0, "routing.rsp", what);
        il_buf_free(&decision);
        il_buf_free(&forwarded);
        forwarded = onward;
        free(env);
    }
    for (size_t j = 0; j < nrouters; j++) il_router_free(routers[j].router);
    il_buf_free(&forwarded);
    free_records(&rs);
    free(text);
    free(policy);
    free(ring);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fputs("usage: conformance <vectors-dir>\n", stderr);
        return 64;
    }
    if (il_abi_version() != IL_ABI_VERSION) {
        fprintf(stderr, "ABI mismatch: header %u, library %u\n", IL_ABI_VERSION, il_abi_version());
        return 70;
    }
    check_cbor(argv[1]);
    check_label(argv[1]);
    check_ccsds(argv[1]);
    check_envelope(argv[1]);
    check_routing(argv[1]);
    printf("C binding (%s): %d passed, %d failed\n", il_version(), passed, failed);
    return failed == 0 ? 0 : 1;
}
