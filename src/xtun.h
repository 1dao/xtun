#ifndef XTUN_H
#define XTUN_H
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include "config.h"
#define XT_MTU 1280
#define XT_MTU_MAX 1400
#define XT_HEADER 8
typedef struct XtDevice XtDevice;
typedef struct { uint64_t oversize, write_ring_full, write_error; } XtDeviceStats;
extern volatile sig_atomic_t xt_stop;
void xt_install_signals(void);
void xt_time_begin(void);
void xt_time_end(void);
uint64_t xt_now(void);
int xt_random(void *, size_t);
int xt_key_write(const char *, const void *, size_t);
XtDevice *xt_device_open(const XtConfig *, char error[256]);
int xt_device_read(XtDevice *, void *, size_t); /* 0 no packet, -1 error */
#ifdef _WIN32
uintptr_t xt_device_fd(const XtDevice *); /* pollable queue wakeup socket */
#else
int xt_device_fd(const XtDevice *);
#endif
int xt_device_write(XtDevice *, const void *, size_t);
int xt_device_set_mtu(XtDevice *, unsigned, char error[256]);
int xt_device_routes(XtDevice *, const XtConfig *, char error[256]);
void xt_device_close(XtDevice *);
XtDeviceStats xt_device_stats(XtDevice *);
int xt_packet_valid(const XtConfig *, const void *, size_t, int inbound);
unsigned xt_mtu_offer(size_t dtls_payload, unsigned ceiling);
int xt_run(const XtConfig *);
#endif
