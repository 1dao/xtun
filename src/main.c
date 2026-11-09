#include "xsock.h"
#define LUA_IMPL
#include "3rd/minilua.h"
#include "xtun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int field_string(lua_State *L, const char *name, char *out, size_t cap, const char *def) {
    lua_getfield(L, -1, name);
    size_t n = 0;
    const char *s = lua_isnil(L, -1) ? def : lua_type(L, -1) == LUA_TSTRING ? lua_tolstring(L, -1, &n) : NULL;
    if (s && !n) n = strlen(s);
    int ok = s && n < cap && !memchr(s, 0, n);
    if (ok) { memcpy(out, s, n); out[n] = 0; }
    else fprintf(stderr, "invalid config field: %s\n", name);
    lua_pop(L, 1); return ok;
}
static int field_number(lua_State *L, const char *name, unsigned *out, unsigned def, unsigned min, unsigned max) {
    lua_getfield(L, -1, name);
    int ok = 0; lua_Integer n = lua_isnil(L, -1) ? def : lua_tointegerx(L, -1, &ok);
    if (lua_isnil(L, -1)) ok = 1;
    ok = ok && n >= min && n <= max;
    if (ok) *out = (unsigned)n; else fprintf(stderr, "invalid config field: %s\n", name);
    lua_pop(L, 1); return ok;
}
static int load_config(XtConfig *c, const char *path) {
    lua_State *L = luaL_newstate();
    if (!L) return 0;
    /* Configurations are trusted local Lua programs, not network input. */
    luaL_openlibs(L);
    if (luaL_dofile(L, path) != LUA_OK || !lua_istable(L, -1)) {
        const char *error = lua_tostring(L, -1);
        fprintf(stderr, "config must return a table: %s\n", error ? error : "invalid return value"); lua_close(L); return 0;
    }
    char local[64], peer[64]; unsigned port;
    int ok = field_string(L, "bind", c->bind_ip, sizeof(c->bind_ip), "0.0.0.0") &&
        field_string(L, "endpoint", c->remote_ip, sizeof(c->remote_ip), "") &&
        field_string(L, "identity", c->identity, sizeof(c->identity), NULL) &&
        field_string(L, "name", c->name, sizeof(c->name), "xtun0") &&
        field_string(L, "psk_file", c->key_file, sizeof(c->key_file), NULL) &&
        field_string(L, "address", local, sizeof(local), NULL) &&
        field_string(L, "peer_address", peer, sizeof(peer), NULL) &&
        field_number(L, "port", &port, 51215, 1, 65535) &&
        field_number(L, "bind_port", &c->bind_port, c->server ? port : 0, 0, 65535) &&
        field_number(L, "run_seconds", &c->run_seconds, 0, 0, 86400) &&
        field_number(L, "session_seconds", &c->session_seconds, 3600, 30, 86400);
    if (ok) {
        c->port = port;
        uint32_t bind;
        ok = *c->identity && *c->name && xt_parse_ip(local, &c->address) &&
             xt_parse_ip(peer, &c->peer_address) && c->address != c->peer_address &&
             xt_parse_ip(c->bind_ip, &bind) && (c->server || xt_parse_ip(c->remote_ip, &c->endpoint_address));
        lua_getfield(L, -1, "full_tunnel");
        if (!lua_isnil(L, -1) && !lua_isboolean(L, -1)) ok = 0;
        c->full_tunnel = lua_toboolean(L, -1);
        lua_pop(L, 1);
#ifndef _WIN32
        if (c->full_tunnel) ok = 0;
#endif
        if (c->full_tunnel && (!ok || c->server || bind || !c->endpoint_address)) ok = 0;
        lua_getfield(L, -1, "dns");
        if (!lua_isnil(L, -1)) {
            const char *dns = lua_type(L, -1) == LUA_TSTRING ? lua_tostring(L, -1) : NULL;
            if (!c->full_tunnel || !xt_parse_ip(dns, &c->dns_address) ||
                !c->dns_address || c->dns_address >= 0xe0000000u ||
                c->dns_address == c->address || c->dns_address == c->endpoint_address) ok = 0;
        }
        lua_pop(L, 1);
        for (const char *p = c->name; *p; ++p)
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) ok = 0;
        if (strlen(c->name) > 15) ok = 0;
    }
    if (ok) {
        c->routes[0] = (XtRoute){c->peer_address, UINT32_MAX, 32}; c->route_count = 1;
        lua_getfield(L, -1, "routes");
        if (!lua_isnil(L, -1)) {
            if (!lua_istable(L, -1) || lua_rawlen(L, -1) >= XT_MAX_ROUTES ||
                (c->full_tunnel && lua_rawlen(L, -1))) ok = 0;
            else for (size_t i = 1; i <= lua_rawlen(L, -1); ++i) {
                lua_rawgeti(L, -1, i);
                const char *s = lua_type(L, -1) == LUA_TSTRING ? lua_tostring(L, -1) : NULL;
                XtRoute r;
                if (!s || !xt_parse_route(s, &r) || r.prefix == 0) ok = 0;
                else {
                    int duplicate = 0;
                    for (unsigned j = 0; j < c->route_count; ++j)
                        if (c->routes[j].network == r.network && c->routes[j].mask == r.mask) duplicate = 1;
                    if (!duplicate) c->routes[c->route_count++] = r;
                }
                lua_pop(L, 1);
            }
        }
        lua_pop(L, 1);
        c->local_networks[0] = (XtRoute){c->address, UINT32_MAX, 32}; c->local_count = 1;
        lua_getfield(L, -1, "local_networks");
        if (!lua_isnil(L, -1)) {
            if (!c->server || !lua_istable(L, -1) || lua_rawlen(L, -1) >= XT_MAX_ROUTES) ok = 0;
            else for (size_t i = 1; i <= lua_rawlen(L, -1); ++i) {
                lua_rawgeti(L, -1, i);
                const char *s = lua_type(L, -1) == LUA_TSTRING ? lua_tostring(L, -1) : NULL;
                XtRoute r;
                if (!s || !xt_parse_route(s, &r)) ok = 0;
                else c->local_networks[c->local_count++] = r;
                lua_pop(L, 1);
            }
        }
        lua_pop(L, 1);
        if (c->full_tunnel) {
            if (c->endpoint_address == c->address || c->endpoint_address == c->peer_address) ok = 0;
        } else if (xt_allowed(c, c->address) || (!c->server && xt_allowed(c, c->endpoint_address))) ok = 0;
    }
    lua_close(L);
    if (!ok) { fputs("invalid IPv4 addresses, name, endpoint, routes, or full_tunnel configuration\n", stderr); return 0; }
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
        fputs("XTun: DTLS encrypted IPv4 tunnel\nUsage:\n  xtun keygen FILE\n  xtun client CONFIG.lua [--check|--probe]\n  xtun server CONFIG.lua [--check|--probe]\n", stderr); return 1;
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
