#ifndef XTUN_H
#define XTUN_H
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#define XT_MTU 1280
#define XT_MAX_ROUTES 16
#define XT_HEADER 8
typedef struct { uint32_t network, mask; unsigned prefix; } XtRoute;
typedef struct {
    int server, check, probe, full_tunnel;
    char bind_ip[64], remote_ip[64], identity[65], name[32];
    char key_file[1024];
    unsigned port, bind_port, run_seconds, session_seconds;
    uint32_t address, peer_address, endpoint_address, dns_address;
    unsigned char key[32];
    XtRoute routes[XT_MAX_ROUTES]; unsigned route_count;
    XtRoute local_networks[XT_MAX_ROUTES]; unsigned local_count;
} XtConfig;
typedef struct XtDevice XtDevice;
extern volatile sig_atomic_t xt_stop;
void xt_install_signals(void);
uint64_t xt_now(void);
int xt_random(void *, size_t);
int xt_key_write(const char *, const void *, size_t);
XtDevice *xt_device_open(const XtConfig *, char error[256]);
int xt_device_read(XtDevice *, void *, size_t); /* 0 no packet, -1 error */
int xt_device_write(XtDevice *, const void *, size_t);
int xt_device_routes(XtDevice *, const XtConfig *, char error[256]);
void xt_device_close(XtDevice *);
uint64_t xt_device_drops(XtDevice *);
int xt_parse_ip(const char *, uint32_t *);
int xt_parse_route(const char *, XtRoute *);
int xt_allowed(const XtConfig *, uint32_t);
int xt_packet_valid(const XtConfig *, const void *, size_t, int inbound);
int xt_run(const XtConfig *);
#endif
