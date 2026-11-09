#include "xsock.h"
#include "xargs.h"
#include "config_tags.h"
#include "xtun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int xt_parse_ip(const char *s, uint32_t *out) {
    struct in_addr a;
    if (!s || inet_pton(AF_INET, s, &a) != 1) return 0;
    *out = ntohl(a.s_addr); return 1;
}
int xt_parse_route(const char *s, XtRoute *r) {
    char ip[64], tail; unsigned prefix;
    if (!s || sscanf(s, "%63[^/]/%u%c", ip, &prefix, &tail) != 2 || prefix > 32 || !xt_parse_ip(ip, &r->network)) return 0;
    r->prefix = prefix; r->mask = prefix ? UINT32_MAX << (32 - prefix) : 0;
    return (r->network & r->mask) == r->network;
}
int xt_allowed(const XtConfig *c, uint32_t ip) {
    if (c->full_tunnel) return ip != c->endpoint_address && ip != c->address;
    for (unsigned i = 0; i < c->route_count; ++i)
        if ((ip & c->routes[i].mask) == c->routes[i].network) return 1;
    return 0;
}
static int field_string(const char *tag, const char *name, char *out, size_t cap, const char *def) {
    const char *s = xt_cfg_value(tag, name);
    if (!s) s = def;
    if (!s || strlen(s) >= cap) {
        fprintf(stderr, "missing or invalid config field: %s\n", name);
        return 0;
    }
    strcpy(out, s);
    return 1;
}
static int field_number(const char *tag, const char *name, unsigned *out, unsigned def, unsigned min, unsigned max) {
    const char *s = xt_cfg_value(tag, name);
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
static int field_routes(const char *tag, const char *name, XtRoute *routes, unsigned *count, int allow_default) {
    const char *s = xt_cfg_value(tag, name);
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
static int read_fields(XtConfig *c, const char *tag) {
    char local[64], peer[64];
    uint32_t bind;
    if (!field_string(tag, "bind", c->bind_ip, sizeof(c->bind_ip), "0.0.0.0") ||
        !field_string(tag, "endpoint", c->remote_ip, sizeof(c->remote_ip), "") ||
        !field_string(tag, "identity", c->identity, sizeof(c->identity), NULL) ||
        !field_string(tag, "name", c->name, sizeof(c->name), "xtun0") ||
        !field_string(tag, "address", local, sizeof(local), NULL) ||
        !field_string(tag, "peer_address", peer, sizeof(peer), NULL) ||
        !field_number(tag, "port", &c->port, 51215, 1, 65535) ||
        !field_number(tag, "bind_port", &c->bind_port, c->server ? c->port : 0, 0, 65535) ||
        !field_number(tag, "run_seconds", &c->run_seconds, 0, 0, 86400) ||
        !field_number(tag, "session_seconds", &c->session_seconds, 3600, 30, 86400)) return 0;
    if (!*c->identity || !*c->name || strlen(c->name) > 15 ||
        !xt_parse_ip(local, &c->address) || !xt_parse_ip(peer, &c->peer_address) ||
        c->address == c->peer_address || !xt_parse_ip(c->bind_ip, &bind) ||
        (!c->server && !xt_parse_ip(c->remote_ip, &c->endpoint_address))) return 0;
    for (const char *p = c->name; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return 0;

    const char *full = xt_cfg_value(tag, "full_tunnel");
    if (full) {
        if (!strcmp(full, "true") || !strcmp(full, "1")) c->full_tunnel = 1;
        else if (strcmp(full, "false") && strcmp(full, "0")) return 0;
    }
#ifndef _WIN32
    if (c->full_tunnel) return 0;
#endif
    if (c->full_tunnel && (c->server || bind || !c->endpoint_address ||
        c->endpoint_address == c->address || c->endpoint_address == c->peer_address)) return 0;
    const char *dns = xt_cfg_value(tag, "dns");
    if (dns && (!c->full_tunnel || !xt_parse_ip(dns, &c->dns_address) ||
        !c->dns_address || c->dns_address >= 0xe0000000u ||
        c->dns_address == c->address || c->dns_address == c->endpoint_address)) return 0;

    c->routes[0] = (XtRoute){c->peer_address, UINT32_MAX, 32}; c->route_count = 1;
    c->local_networks[0] = (XtRoute){c->address, UINT32_MAX, 32}; c->local_count = 1;
    const char *routes = xt_cfg_value(tag, "routes");
    if ((c->full_tunnel && routes && *routes) ||
        (!c->server && xt_cfg_value(tag, "local_networks")) ||
        !field_routes(tag, "routes", c->routes, &c->route_count, 0) ||
        !field_routes(tag, "local_networks", c->local_networks, &c->local_count, 1)) return 0;
    return c->full_tunnel ||
           (!xt_allowed(c, c->address) && (c->server || !xt_allowed(c, c->endpoint_address)));
}
int xt_load_config(XtConfig *c, const char *path, const char *tag) {
    if (xargs_load_config(path) != 0) {
        fprintf(stderr, "cannot open CFG file: %s\n", path);
        return 0;
    }
    const char *tag_list = xargs_get("tags");
    XtTag tags[XT_TAG_LIMIT];
    int count = xt_parse_tags(tag_list, tags);
    if (tag_list || tag) {
        if (!c->server && !tag && count == 1) tag = tags[0];
        if (c->server || !tag || count <= 0 || xt_find_tag(tags, count, tag) < 0) {
            fputs("invalid or missing client tag (use --tag TAG from the CFG tags list)\n", stderr);
            xargs_cleanup();
            return 0;
        }
    }
    int ok = read_fields(c, tag);
    const char *psk = xt_cfg_value(tag, "psk");
    if (tag && !psk) psk = xargs_get("psk");
    char hex[65];
    if (ok && psk && strlen(psk) == 64) memcpy(hex, psk, sizeof(hex));
    else ok = 0;
    xargs_cleanup();
    if (!ok) { fputs("invalid XTun configuration or missing 64-hex-character psk\n", stderr); return 0; }
    for (unsigned i = 0; i < 32; ++i) {
        unsigned v = 0;
        for (unsigned j = 0; j < 2; ++j) {
            unsigned char ch = (unsigned char)hex[i*2+j];
            if (ch >= '0' && ch <= '9') ch -= '0';
            else if (ch >= 'a' && ch <= 'f') ch = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') ch = ch - 'A' + 10;
            else { memset(hex, 0, sizeof(hex)); memset(c->key, 0, sizeof(c->key));
                   fputs("psk must contain exactly 64 hex characters\n", stderr); return 0; }
            v = v * 16 + ch;
        }
        c->key[i] = (unsigned char)v;
    }
    memset(hex, 0, sizeof(hex)); return 1;
}
