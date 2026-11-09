#include "xsock.h"
#include "xargs.h"
#include "xtun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int field_string(const char *name, char *out, size_t cap, const char *def) {
    const char *s = xargs_get(name);
    if (!s) s = def;
    if (!s || strlen(s) >= cap) {
        fprintf(stderr, "missing or invalid config field: %s\n", name);
        return 0;
    }
    strcpy(out, s);
    return 1;
}
static int field_number(const char *name, unsigned *out, unsigned def, unsigned min, unsigned max) {
    const char *s = xargs_get(name);
    if (!s) { *out = def; return 1; }
    char *end;
    unsigned long n = strtoul(s, &end, 10);
    if (*s < '0' || *s > '9' || *end || n < min || n > max) {
        fprintf(stderr, "invalid config field: %s\n", name);
        return 0;
    }
    *out = (unsigned)n;
    return 1;
}
static int field_routes(const char *name, XtRoute *routes, unsigned *count, int allow_default) {
    const char *s = xargs_get(name);
    if (!s || !*s) return 1;
    for (unsigned entries = 1; entries < XT_MAX_ROUTES; ++entries) {
        while (*s == ' ' || *s == '\t') ++s;
        const char *comma = strchr(s, ',');
        const char *end = comma ? comma : s + strlen(s);
        while (end > s && (end[-1] == ' ' || end[-1] == '\t')) --end;
        char cidr[32];
        if (end == s || (size_t)(end - s) >= sizeof(cidr)) break;
        memcpy(cidr, s, (size_t)(end - s));
        cidr[end - s] = 0;
        XtRoute route;
        if (!xt_parse_route(cidr, &route) || (!allow_default && route.prefix == 0)) break;
        unsigned i = 0;
        while (i < *count && (routes[i].network != route.network || routes[i].mask != route.mask)) ++i;
        if (i == *count) routes[(*count)++] = route;
        if (!comma) return 1;
        s = comma + 1;
    }
    fprintf(stderr, "invalid config route list: %s\n", name);
    return 0;
}
static int read_fields(XtConfig *c) {
    char local[64], peer[64];
    uint32_t bind;
    if (!field_string("bind", c->bind_ip, sizeof(c->bind_ip), "0.0.0.0") ||
        !field_string("endpoint", c->remote_ip, sizeof(c->remote_ip), "") ||
        !field_string("identity", c->identity, sizeof(c->identity), NULL) ||
        !field_string("name", c->name, sizeof(c->name), "xtun0") ||
        !field_string("psk_file", c->key_file, sizeof(c->key_file), NULL) ||
        !field_string("address", local, sizeof(local), NULL) ||
        !field_string("peer_address", peer, sizeof(peer), NULL) ||
        !field_number("port", &c->port, 51215, 1, 65535) ||
        !field_number("bind_port", &c->bind_port, c->server ? c->port : 0, 0, 65535) ||
        !field_number("run_seconds", &c->run_seconds, 0, 0, 86400) ||
        !field_number("session_seconds", &c->session_seconds, 3600, 30, 86400)) return 0;
    if (!*c->identity || !*c->key_file || !*c->name || strlen(c->name) > 15 ||
        !xt_parse_ip(local, &c->address) || !xt_parse_ip(peer, &c->peer_address) ||
        c->address == c->peer_address || !xt_parse_ip(c->bind_ip, &bind) ||
        (!c->server && !xt_parse_ip(c->remote_ip, &c->endpoint_address))) return 0;
    for (const char *p = c->name; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return 0;

    const char *full = xargs_get("full_tunnel");
    if (full) {
        if (!strcmp(full, "true") || !strcmp(full, "1")) c->full_tunnel = 1;
        else if (strcmp(full, "false") && strcmp(full, "0")) return 0;
    }
#ifndef _WIN32
    if (c->full_tunnel) return 0;
#endif
    if (c->full_tunnel && (c->server || bind || !c->endpoint_address ||
        c->endpoint_address == c->address || c->endpoint_address == c->peer_address)) return 0;
    const char *dns = xargs_get("dns");
    if (dns && (!c->full_tunnel || !xt_parse_ip(dns, &c->dns_address) ||
        !c->dns_address || c->dns_address >= 0xe0000000u ||
        c->dns_address == c->address || c->dns_address == c->endpoint_address)) return 0;

    c->routes[0] = (XtRoute){c->peer_address, UINT32_MAX, 32}; c->route_count = 1;
    c->local_networks[0] = (XtRoute){c->address, UINT32_MAX, 32}; c->local_count = 1;
    const char *routes = xargs_get("routes");
    if ((c->full_tunnel && routes && *routes) ||
        (!c->server && xargs_get("local_networks")) ||
        !field_routes("routes", c->routes, &c->route_count, 0) ||
        !field_routes("local_networks", c->local_networks, &c->local_count, 1)) return 0;
    return c->full_tunnel ||
           (!xt_allowed(c, c->address) && (c->server || !xt_allowed(c, c->endpoint_address)));
}
static int load_config(XtConfig *c, const char *path) {
    if (xargs_load_config(path) != 0) {
        fputs("cannot open CFG file\n", stderr);
        return 0;
    }
    int ok = read_fields(c);
    xargs_cleanup();
    if (!ok) { fputs("invalid XTun configuration (expected key=value CFG)\n", stderr); return 0; }
    /* Relative PSK paths are resolved relative to the config, never its content. */
    if (c->key_file[0] != '/' && c->key_file[0] != '\\' && !(strlen(c->key_file) > 1 && c->key_file[1] == ':')) {
        const char *slash = strrchr(path, '/'), *back = strrchr(path, '\\');
        if (!slash || (back && back > slash)) slash = back;
        if (slash) {
            char joined[1024]; size_t n = (size_t)(slash - path + 1);
            if (n + strlen(c->key_file) >= sizeof(joined)) return 0;
            memcpy(joined, path, n); strcpy(joined + n, c->key_file); strcpy(c->key_file, joined);
        }
    }
    FILE *f = fopen(c->key_file, "rb");
    if (!f) { fputs("cannot open PSK file\n", stderr); return 0; }
    char hex[68] = {0}; size_t n = fread(hex, 1, sizeof(hex), f); fclose(f);
    while (n && (hex[n-1] == '\n' || hex[n-1] == '\r')) --n;
    if (n != 64) { fputs("PSK must contain exactly 64 hex characters\n", stderr); return 0; }
    for (unsigned i = 0; i < 32; ++i) {
        unsigned v = 0;
        for (unsigned j = 0; j < 2; ++j) {
            unsigned char ch = (unsigned char)hex[i*2+j];
            if (ch >= '0' && ch <= '9') ch -= '0';
            else if (ch >= 'a' && ch <= 'f') ch = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') ch = ch - 'A' + 10;
            else { memset(hex, 0, sizeof(hex)); return 0; }
            v = v * 16 + ch;
        }
        c->key[i] = (unsigned char)v;
    }
    memset(hex, 0, sizeof(hex)); return 1;
}
int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "keygen")) {
        unsigned char key[32]; char hex[65];
        if (!xt_random(key, sizeof(key))) return 1;
        for (unsigned i = 0; i < 32; ++i) snprintf(hex + 2*i, 3, "%02x", key[i]);
        int ok = xt_key_write(argv[2], hex, 64);
        memset(key, 0, sizeof(key)); memset(hex, 0, sizeof(hex));
        if (!ok) fputs("cannot create key file (existing files are never overwritten)\n", stderr);
        return ok ? 0 : 1;
    }
    if (argc < 3 || argc > 4 || (strcmp(argv[1], "client") && strcmp(argv[1], "server"))) {
        fputs("XTun: DTLS encrypted IPv4 tunnel\nUsage:\n  xtun keygen FILE\n  xtun client CONFIG.cfg [--check|--probe]\n  xtun server CONFIG.cfg [--check|--probe]\n", stderr); return 1;
    }
    XtConfig cfg = {0}; cfg.server = !strcmp(argv[1], "server");
    if (argc == 4) {
        if (!strcmp(argv[3], "--check")) cfg.check = 1;
        else if (!strcmp(argv[3], "--probe")) cfg.probe = 1;
#ifdef _WIN32
        else if (!cfg.server && !strcmp(argv[3], "--gui-child") &&
                 GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_PIPE) cfg.managed = 1;
#endif
        else { fputs("unknown option\n", stderr); return 1; }
    }
    if (!load_config(&cfg, argv[2])) return 1;
    int rc;
    if (cfg.check) { puts("Configuration valid (no network changes)"); rc = 0; }
    else rc = xt_run(&cfg);
    volatile unsigned char *secret = cfg.key;
    for (size_t i = 0; i < sizeof(cfg.key); ++i) secret[i] = 0;
    return rc;
}
