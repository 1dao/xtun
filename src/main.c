#include "xsock.h"
#include "config.h"
#include "xtun.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
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
        fputs("XTun: DTLS encrypted IPv4 tunnel\nUsage:\n  xtun keygen [FILE]\n  xtun client [--tag TAG] [--check|--probe]\n  xtun server [--check|--probe]\n", stderr); return 1;
    }
    XtConfig cfg = {0}; cfg.server = !strcmp(argv[1], "server");
    const char *tag = NULL;
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--tag") && !cfg.server && !tag &&
            i + 1 < argc && xt_tag_valid(argv[i + 1])) tag = argv[++i];
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
    int rc;
    if (cfg.check) { puts("Configuration valid (no network changes)"); rc = 0; }
    else rc = xt_run(&cfg);
    volatile unsigned char *secret = cfg.key;
    for (size_t i = 0; i < sizeof(cfg.key); ++i) secret[i] = 0;
    return rc;
}
