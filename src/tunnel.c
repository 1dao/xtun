#include "xtun.h"
#include "xdtls.h"
#include "xudp.h"
#include "xpoll.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define XT_QUEUE 64
enum { READY = 1, DATA, PING, PONG, CLOSE };
volatile sig_atomic_t xt_stop;

static uint32_t be32(const unsigned char *p) { return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }
static void put32(unsigned char *p, uint32_t n) { p[0]=n>>24; p[1]=n>>16; p[2]=n>>8; p[3]=n; }
int xt_packet_valid(const XtConfig *c, const void *bytes, size_t n, int inbound) {
    const unsigned char *p = bytes;
    if (n < 20 || n > XT_MTU || (p[0] >> 4) != 4) return 0;
    size_t header = (p[0] & 15) * 4;
    if (header < 20 || header > n || ((size_t)p[2]<<8 | p[3]) != n) return 0;
    unsigned sum = 0;
    for (size_t i = 0; i < header; i += 2) sum += ((unsigned)p[i]<<8) | p[i+1];
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    if (sum != 65535) return 0;
    uint32_t src = be32(p+12), dst = be32(p+16);
    /* Client is a host; server may route other IPv4 networks behind itself. */
    uint32_t local = inbound ? dst : src;
    int local_allowed = 0;
    for (unsigned i = 0; i < c->local_count; ++i)
        if ((local & c->local_networks[i].mask) == c->local_networks[i].network) local_allowed = 1;
    return local_allowed && xt_allowed(c, inbound ? src : dst);
}
typedef struct {
    const XtConfig *cfg;
    xUdp *udp;
    xUdpAddress peer;
    xDtls *dtls;
    XtDevice *dev;
    uint64_t now, born, last_rx, last_tx, last_ready, last_ping, records;
    uint64_t tx_packets, rx_packets, drops, tx_bytes, rx_bytes;
    uint64_t drop_peer, drop_dtls_input, drop_tx_queue, drop_frame, drop_ip, drop_tun_write;
    unsigned head, count;
    struct { size_t len; unsigned char bytes[XT_HEADER + XT_MTU]; } queue[XT_QUEUE];
    int active, routes, failed, probe_ok, pong;
} Tunnel;
static int dtls_send(void *p, const unsigned char *data, size_t n) {
    Tunnel *t = p; int error;
    int rc = xudp_sendto(t->udp, data, n, &t->peer, &error);
    return rc == XUDP_OK ? (int)n : rc == XUDP_WOULD_BLOCK ? XDTLS_AGAIN : XDTLS_ERROR;
}
static int new_session(Tunnel *t) {
    char error[256], id[96];
    snprintf(id, sizeof(id), "%s:%u", t->peer.ip, t->peer.port);
    xDtlsConfig cfg = {0}; cfg.server = t->cfg->server; cfg.psk = t->cfg->key;
    cfg.identity = t->cfg->identity; cfg.transport_id = id; cfg.transport_id_len = strlen(id);
    cfg.send = dtls_send; cfg.userdata = t; cfg.now_ms = t->now;
    t->dtls = xdtls_create(&cfg, error);
    if (!t->dtls) { fprintf(stderr, "DTLS initialization failed: %s\n", error); return 0; }
    t->born = t->last_rx = t->last_tx = t->now;
    t->last_ready = t->last_ping = 0; t->records = 0;
    return 1;
}
static void udp_receive(xUdp *u, const char *data, size_t n, const xUdpAddress *from, void *p) {
    Tunnel *t = p; (void)u;
    if (!t->dtls) {
        /* Only a plausible DTLS handshake can occupy the single bounded slot. */
        if (!t->cfg->server || n < 13 || (unsigned char)data[0] != 22 ||
            (unsigned char)data[1] != 0xfe || ((unsigned char)data[2] != 0xff && (unsigned char)data[2] != 0xfd)) return;
        t->peer = *from;
        if (xt_allowed(t->cfg, ntohl(inet_addr(from->ip)))) { ++t->drops; ++t->drop_peer; return; }
        if (!new_session(t)) { t->failed = 1; return; }
    }
    if (from->port != t->peer.port || strcmp(from->ip, t->peer.ip)) { ++t->drops; ++t->drop_peer; return; }
    if (xdtls_feed(t->dtls, data, n)) { ++t->drops; ++t->drop_dtls_input; }
}
static void udp_error(xUdp *u, int error, bool fatal, void *p) {
    (void)u;
    if (fatal) { fprintf(stderr, "fatal UDP error: %d\n", error); ((Tunnel *)p)->failed = 1; }
}
static int enqueue(Tunnel *t, unsigned type, const void *data, size_t n) {
    /* Reserve four slots for control. All buffers have fixed byte bounds. */
    if (n > XT_MTU || t->count >= (type == DATA ? XT_QUEUE-4 : XT_QUEUE)) { ++t->drops; ++t->drop_tx_queue; return 0; }
    unsigned tail = (t->head + t->count) % XT_QUEUE;
    unsigned char *p = t->queue[tail].bytes;
    p[0] = 1; p[1] = (unsigned char)type; p[2] = p[3] = 0; put32(p+4, (uint32_t)n);
    if (n) memcpy(p+8, data, n);
    t->queue[tail].len = XT_HEADER + n; ++t->count; return 1;
}
static void queue_ready(Tunnel *t) {
    unsigned char p[12] = {0}; put32(p, t->cfg->address); put32(p+4, t->cfg->peer_address);
    p[8] = XT_MTU >> 8; p[9] = XT_MTU & 255;
    if (enqueue(t, READY, p, sizeof(p))) t->last_ready = t->now;
}
static int flush(Tunnel *t) {
    for (unsigned i = 0; i < XT_QUEUE && t->count; ++i) {
        unsigned head = t->head; size_t n = t->queue[head].len;
        int rc = xdtls_write(t->dtls, t->queue[head].bytes, n);
        if (rc == XDTLS_AGAIN) return 1;
        if (rc != (int)n) return 0;
        if (t->queue[head].bytes[1] == DATA) { ++t->tx_packets; t->tx_bytes += n-XT_HEADER; }
        ++t->records; t->last_tx = t->now;
        t->head = (head+1) % XT_QUEUE; --t->count;
    }
    return 1;
}
static int receive_messages(Tunnel *t) {
    unsigned char p[2048];
    for (unsigned i = 0; i < 64; ++i) {
        int rc = xdtls_read(t->dtls, p, sizeof(p));
        if (rc == XDTLS_AGAIN) return 1;
        if (rc < XT_HEADER || p[0] != 1 || p[2] || p[3] || be32(p+4) != (unsigned)rc-XT_HEADER) {
            if (rc < 0) return 0;
            ++t->drops; ++t->drop_frame; continue;
        }
        size_t n = (size_t)rc-XT_HEADER;
        if (p[1] == READY) {
            if (n != 12 || be32(p+8) != t->cfg->peer_address || be32(p+12) != t->cfg->address ||
                ((unsigned)p[16]<<8 | p[17]) != XT_MTU || p[18] || p[19]) {
                fputs("peer tunnel parameters mismatch\n", stderr); return 0;
            }
            t->last_rx = t->now;
            if (t->now - t->last_ready >= 500 || !t->active) queue_ready(t);
            if (!t->active) {
                if (!t->cfg->probe && !t->routes) {
                    char error[256];
                    if (!xt_device_routes(t->dev, t->cfg, error)) { fprintf(stderr, "routes: %s\n", error); t->failed = 1; return 0; }
                    t->routes = 1;
                }
                t->active = 1;
                printf("READY %s mtu=%d\n", xdtls_suite(t->dtls), XT_MTU); fflush(stdout);
            }
        } else if (p[1] == DATA && t->active && !t->cfg->probe) {
            if (!xt_packet_valid(t->cfg, p+8, n, 1)) { ++t->drops; ++t->drop_ip; continue; }
            t->last_rx = t->now;
            if (xt_device_write(t->dev, p+8, n) > 0) { ++t->rx_packets; t->rx_bytes += n; }
            else { ++t->drops; ++t->drop_tun_write; }
        } else if (p[1] == PING && t->active && n == 8) {
            t->last_rx = t->now; enqueue(t, PONG, p+8, n);
        } else if (p[1] == PONG && t->active && n == 8) {
            t->last_rx = t->now; t->pong = 1;
            if (t->cfg->probe) { puts("PROBE OK: authenticated bidirectional datagrams"); fflush(stdout); t->probe_ok = 1; }
        } else if (p[1] == CLOSE && !n) return 0;
        else { ++t->drops; ++t->drop_frame; }
    }
    return 1;
}
static void reset(Tunnel *t) {
    xdtls_close(t->dtls); xdtls_destroy(t->dtls); t->dtls = NULL;
    t->count = t->head = 0; t->active = t->pong = 0;
}
int xt_run(const XtConfig *cfg) {
    Tunnel *t = calloc(1, sizeof(*t));
    if (!t) return 1;
    t->cfg = cfg; t->now = xt_now();
    uint64_t start = t->now, retry_at = start;
    char error[256]; int rc = 1;
    xt_install_signals();
    if (socket_init() || xpoll_init()) goto done;
    xUdpConfig udp_cfg = {0}; udp_cfg.max_datagram = XDTLS_MAX_RECORD;
    /* Never drain more records per poll than an empty DTLS queue can hold. */
    udp_cfg.recv_budget = XDTLS_RX_SLOTS;
    udp_cfg.on_datagram = udp_receive; udp_cfg.on_error = udp_error; udp_cfg.userdata = t;
    t->udp = xudp_bind(cfg->bind_ip, cfg->bind_port, &udp_cfg, error);
    if (!t->udp) { fprintf(stderr, "UDP bind: %s\n", error); goto done; }
    if (!cfg->server && xudp_address(cfg->remote_ip, (int)cfg->port, &t->peer)) goto done;
    if (!cfg->probe) {
        t->dev = xt_device_open(cfg, error);
        if (!t->dev) { fprintf(stderr, "virtual adapter: %s\n", error); goto done; }
    }
    xUdpAddress bound; xudp_sockname(t->udp, &bound);
    printf("LISTEN %s:%u mode=%s%s\n", bound.ip, bound.port, cfg->server ? "server" : "client", cfg->probe ? " probe" : ""); fflush(stdout);
    while (!xt_stop && !t->failed) {
#ifdef _WIN32
        if (cfg->managed && !PeekNamedPipe(GetStdHandle(STD_INPUT_HANDLE), NULL, 0, NULL, NULL, NULL)) {
            xt_stop = 1;
            break;
        }
#endif
        t->now = xt_now();
        if (cfg->run_seconds && t->now-start >= (uint64_t)cfg->run_seconds*1000) { rc = cfg->probe && !t->probe_ok ? 1 : 0; break; }
        if (!t->dtls && !cfg->server && t->now >= retry_at && !new_session(t)) { t->failed = 1; break; }
        if (t->dtls) {
            int step = xdtls_step(t->dtls, t->now);
            if (step < 0 || t->now-t->last_rx > (t->active ? 60000u : 15000u) ||
                t->now-t->born >= (uint64_t)cfg->session_seconds*1000 || t->records >= (1u<<24)) {
                fprintf(stderr, "session reset: error=%d\n", xdtls_last_error(t->dtls));
                reset(t); retry_at = t->now+1000;
            } else if (step == 1) {
                if (!t->active && t->now-t->last_ready >= 1000) queue_ready(t);
                if (!receive_messages(t)) { reset(t); retry_at = t->now+1000; }
                else {
                    if (t->active && t->now-t->last_ping >= (cfg->probe ? 1000u : 20000u)) {
                        unsigned char stamp[8]; put32(stamp, (uint32_t)(t->now>>32)); put32(stamp+4, (uint32_t)t->now);
                        if (enqueue(t, PING, stamp, 8)) t->last_ping = t->now;
                    }
                    if (t->active && !cfg->probe) {
                        unsigned char packet[65536];
                        for (unsigned i = 0; i < 32 && t->count < XT_QUEUE-4; ++i) {
                            int n = xt_device_read(t->dev, packet, sizeof(packet));
                            if (n < 0) { t->failed = 1; break; }
                            if (!n) break;
                            if (xt_packet_valid(cfg, packet, (size_t)n, 0)) enqueue(t, DATA, packet, (size_t)n);
                            else { ++t->drops; ++t->drop_ip; }
                        }
                    }
                    if (!flush(t)) { reset(t); retry_at = t->now+1000; }
                }
            }
        }
        if (cfg->probe && !cfg->server && t->probe_ok) { rc = 0; break; }
        xpoll_poll(5);
    }
    if (xt_stop) rc = 0;
    if (t->failed) rc = 1;
done:
    printf("STATS tx_packets=%llu rx_packets=%llu tx_bytes=%llu rx_bytes=%llu drops=%llu "
        "drop_peer=%llu drop_dtls_input=%llu drop_tx_queue=%llu drop_frame=%llu "
        "drop_ip=%llu drop_tun_write=%llu drop_device=%llu\n",
        (unsigned long long)t->tx_packets, (unsigned long long)t->rx_packets,
        (unsigned long long)t->tx_bytes, (unsigned long long)t->rx_bytes,
        (unsigned long long)(t->drops + xt_device_drops(t->dev)),
        (unsigned long long)t->drop_peer, (unsigned long long)t->drop_dtls_input,
        (unsigned long long)t->drop_tx_queue, (unsigned long long)t->drop_frame,
        (unsigned long long)t->drop_ip, (unsigned long long)t->drop_tun_write,
        (unsigned long long)xt_device_drops(t->dev));
    xUdpStats udp_stats = {0};
    if (t->udp) xudp_get_stats(t->udp, &udp_stats);
    printf("UDP_STATS rx_datagrams=%llu tx_datagrams=%llu rx_oversize=%llu "
        "receive_errors=%llu send_errors=%llu send_would_block=%llu\n",
        (unsigned long long)udp_stats.datagrams_received, (unsigned long long)udp_stats.datagrams_sent,
        (unsigned long long)udp_stats.dropped_oversize, (unsigned long long)udp_stats.receive_errors,
        (unsigned long long)udp_stats.send_errors, (unsigned long long)udp_stats.send_would_block);
    if (xdtls_ready(t->dtls) && t->active && !t->count) {
        enqueue(t, CLOSE, NULL, 0); (void)flush(t);
    }
    reset(t); xt_device_close(t->dev); xudp_destroy(t->udp); xpoll_uninit(); socket_cleanup();
    free(t); return rc;
}
