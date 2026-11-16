#include "xsock.h"
#include "xdaemon.h"
#include "config.h"
#include "xtun.h"
#include <stdio.h>
#include <string.h>

static void print_help(FILE *out) {
    fputs("XTun: DTLS encrypted IPv4 tunnel\n"
          "Usage:\n"
          "  xtun keygen [FILE]\n"
          "  xtun client [--tag TAG] [--check|--probe]\n"
          "  xtun server [--foreground] [--check|--probe]\n"
          "  xtun --help\n"
          "\n"
          "Configuration files: client.cfg / server.cfg in the current directory.\n"
          "Generate a key with 'xtun keygen'; replace <PSK> in BOTH files with\n"
          "the same generated 64-hex-character key. Replace 192.0.2.2 with\n"
          "the server's reachable numeric IPv4 address.\n"
          "\n"
          "Example client.cfg (192.168.1.0/24 <-> server-side 10.x networks):\n"
          "  endpoint=192.0.2.2\n"
          "  port=51215\n"
          "  psk=<PSK>\n"
          "  address=10.77.0.2\n"
          "  peer_address=10.77.0.1\n"
          "  full_tunnel=false\n"
          "  routes=10.10.0.0/16,10.20.0.0/16\n"
          "  local_networks=192.168.1.0/24\n"
          "\n"
          "Example server.cfg:\n"
          "  bind=0.0.0.0\n"
          "  port=51215\n"
          "  psk=<PSK>\n"
          "  address=10.77.0.1\n"
          "  peer_address=10.77.0.2\n"
          "  local_networks=10.10.0.0/16,10.20.0.0/16\n"
          "  routes=192.168.1.0/24\n"
          "\n"
          "Check configuration without network changes:\n"
          "  xtun client --check\n"
          "  xtun server --check\n"
          "\n"
          "Replace the example networks with your actual LAN networks.\n"
          "On either peer, routes lists remote networks (comma-separated IPv4\n"
          "CIDRs); local_networks authorizes networks behind that peer.\n"
          "For LAN-to-LAN access, enable OS IPv4 forwarding and allow firewall\n"
          "forwarding on BOTH peers. On each LAN gateway, route the remote LAN\n"
          "via the local XTun machine's LAN IP. XTun does not configure these\n"
          "settings. Omit routes/local_networks for tunnel peer access only.\n"
          "Windows clients can use full_tunnel=true (the Windows default);\n"
          "the server then needs local_networks=0.0.0.0/0, IPv4 forwarding\n"
          "and NAT or return routing. See examples/ for Linux gateway hooks.\n"
          "Linux servers run in the background by default and log to server.log;\n"
          "use --foreground to keep the server in the terminal.\n", out);
}

int main(int argc, char **argv) {
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
        print_help(stdout);
        return 0;
    }
    if ((argc == 2 || argc == 3) && !strcmp(argv[1], "keygen")) {
        unsigned char key[32]; char hex[65];
        if (!xt_random(key, sizeof(key))) return 1;
        for (unsigned i = 0; i < 32; ++i) snprintf(hex + 2*i, 3, "%02x", key[i]);
        int ok = argc == 2 ? puts(hex) >= 0 : xt_key_write(argv[2], hex, 64);
        memset(key, 0, sizeof(key)); memset(hex, 0, sizeof(hex));
        if (!ok) fputs("cannot create key file (existing files are never overwritten)\n", stderr);
        return ok ? 0 : 1;
    }
    if (argc < 2 || argc > 5 || (strcmp(argv[1], "client") && strcmp(argv[1], "server"))) {
        print_help(stderr); return 1;
    }
    XtConfig cfg = {0}; cfg.server = !strcmp(argv[1], "server");
    const char *tag = NULL;
    int foreground = 0;
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--tag") && !cfg.server && !tag &&
            i + 1 < argc && xt_tag_valid(argv[i + 1])) tag = argv[++i];
        else if (!strcmp(argv[i], "--foreground") && cfg.server && !foreground) foreground = 1;
        else if (!strcmp(argv[i], "--check") && !cfg.check && !cfg.probe && !cfg.managed) cfg.check = 1;
        else if (!strcmp(argv[i], "--probe") && !cfg.check && !cfg.probe && !cfg.managed) cfg.probe = 1;
#ifdef _WIN32
        else if (!cfg.server && !cfg.check && !cfg.probe && !cfg.managed &&
                 !strcmp(argv[i], "--gui-child") &&
                 GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_PIPE) cfg.managed = 1;
#endif
        else { fputs("unknown option\n", stderr); return 1; }
    }
    const char *path = cfg.server ? XT_SERVER_CONFIG : XT_CLIENT_CONFIG;
    if (!xt_load_config(&cfg, path, tag)) return 1;
    int daemon_initialized = 0;
#ifndef _WIN32
    if (cfg.server && !cfg.check && !cfg.probe && !foreground) {
        /* Check log access before detaching so a bad path fails visibly. */
        FILE *log = fopen("server.log", "a");
        if (!log) { perror("server.log"); return 1; }
        fclose(log);
        fflush(NULL);
        if (xdaemon_init(1)) {
            perror("daemon initialization");
            xdaemon_uninit();
            return 1;
        }
        daemon_initialized = 1;
        if (!freopen("server.log", "a", stdout) || !freopen("server.log", "a", stderr)) {
            xdaemon_uninit();
            return 1;
        }
        setvbuf(stdout, NULL, _IOLBF, 0);
    }
#else
    (void)foreground;
#endif
    int rc;
    if (cfg.check) { puts("Configuration valid (no network changes)"); rc = 0; }
    else rc = xt_run(&cfg);
    volatile unsigned char *secret = cfg.key;
    for (size_t i = 0; i < sizeof(cfg.key); ++i) secret[i] = 0;
    if (daemon_initialized) xdaemon_uninit();
    return rc;
}
