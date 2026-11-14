#include "xtun.h"
#include "xdtls.h"
#include "xudp.h"
#include "xpoll.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define XT_QUEUE 64
#define XT_READ_BUDGET 32
/* Linux clamps SO_RCVBUF/SO_SNDBUF to 2x rmem_max and ignores the rest. */
#define XT_UDP_BUFFER (4*1024*1024)
enum { READY = 1, DATA, PING, PONG, CLOSE };
volatile sig_atomic_t xt_stop;

static uint32_t be32(const unsigned char *p) { return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }
static void put32(unsigned char *p, uint32_t n) { p[0]=n>>24; p[1]=n>>16; p[2]=n>>8; p[3]=n; }
unsigned xt_mtu_offer(size_t payload, unsigned ceiling) {
    if (payload < XT_HEADER + XT_MTU) return 0;
    size_t mtu = payload - XT_HEADER;
    if (mtu > XT_MTU_MAX) mtu = XT_MTU_MAX;
    if (ceiling && mtu > ceiling) mtu = ceiling;
    return mtu >= XT_MTU ? (unsigned)mtu : 0;
}
int xt_packet_valid(const XtConfig *c, const void *bytes, size_t n, int inbound) {
    const unsigned char *p = bytes;
    if (n < 20 || n > (c->mtu ? c->mtu : XT_MTU) || (p[0] >> 4) != 4) return 0;
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
    XtConfig *cfg;
    xUdp *udp;
    xUdpAddress peer;
    xDtls *dtls;
    XtDevice *dev;
    uint64_t now, born, last_rx, last_tx, last_ready, last_ping, records;
    uint64_t tx_packets, rx_packets, drops, tx_bytes, rx_bytes;
    uint64_t drop_peer, drop_dtls_input, drop_tx_queue, drop_frame, drop_ip, drop_tun_write;
    unsigned head, count;
    unsigned mtu_offer, peer_offer, mtu_selected;
    struct { size_t len; unsigned char bytes[XT_HEADER + XT_MTU_MAX]; } queue[XT_QUEUE];
    int active, routes, failed, probe_ok, pong;
} Tunnel;
static int dtls_send(void *p, const unsigned char *data, size_t n) {
    Tunnel *t = p; int error;
    int rc = xudp_sendto(t->udp, data, n, &t->peer, &error);
    if (xudp_wait_writable(t->udp, rc == XUDP_WOULD_BLOCK) != XUDP_OK) return XDTLS_ERROR;
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
    /* Stop this receive pass as soon as the downstream queue is full. */
    if (!xdtls_input_space(t->dtls)) xudp_pause_read(t->udp);
}
static void udp_error(xUdp *u, int error, bool fatal, void *p) {
    (void)u;
    if (fatal) { fprintf(stderr, "fatal UDP error: %d\n", error); ((Tunnel *)p)->failed = 1; }
}
static int enqueue(Tunnel *t, unsigned type, const void *data, size_t n) {
    /* Reserve four slots for control. All buffers have fixed byte bounds. */
    if (n > XT_MTU_MAX || (type == DATA && n > t->cfg->mtu) ||
        t->count >= (type == DATA ? XT_QUEUE-4 : XT_QUEUE)) { ++t->drops; ++t->drop_tx_queue; return 0; }
    unsigned tail = (t->head + t->count) % XT_QUEUE;
    unsigned char *p = t->queue[tail].bytes;
    p[0] = 1; p[1] = (unsigned char)type; p[2] = p[3] = 0; put32(p+4, (uint32_t)n);
    if (n) memcpy(p+8, data, n);
    t->queue[tail].len = XT_HEADER + n; ++t->count; return 1;
}
static void queue_ready(Tunnel *t) {
    unsigned char p[16] = {0}; put32(p, t->cfg->address); put32(p+4, t->cfg->peer_address);
    p[8] = t->mtu_offer >> 8; p[9] = t->mtu_offer & 255;
    p[10] = t->mtu_selected >> 8; p[11] = t->mtu_selected & 255;
    p[12] = 1; /* MTU negotiation version; selected=0 until peer offer arrives */
    if (enqueue(t, READY, p, sizeof(p))) t->last_ready = t->now;
}
static int flush(Tunnel *t, unsigned budget) {
    for (unsigned i = 0; i < budget && t->count; ++i) {
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
            if (n != 16 || be32(p+8) != t->cfg->peer_address || be32(p+12) != t->cfg->address ||
                p[20] != 1 || p[21] || p[22] || p[23]) {
                fputs("peer tunnel parameters mismatch\n", stderr); return 0;
            }
            unsigned offer = (unsigned)p[16]<<8 | p[17];
            unsigned confirmed = (unsigned)p[18]<<8 | p[19];
            unsigned selected = offer < t->mtu_offer ? offer : t->mtu_offer;
            if (offer < XT_MTU || offer > XT_MTU_MAX ||
                (t->peer_offer && offer != t->peer_offer) || (confirmed && confirmed != selected)) {
                fputs("peer MTU negotiation mismatch\n", stderr); return 0;
            }
            t->peer_offer = offer; t->mtu_selected = selected;
            t->last_rx = t->now;
            if (t->now - t->last_ready >= 500 || !t->active) queue_ready(t);
            if (!t->active && confirmed) {
                char error[256];
                if (!t->cfg->probe && !xt_device_set_mtu(t->dev, selected, error)) {
                    fprintf(stderr, "MTU: %s\n", error); t->failed = 1; return 0;
                }
                t->cfg->mtu = selected;
                if (!t->cfg->probe && !t->routes) {
                    char error[256];
                    if (!xt_device_routes(t->dev, t->cfg, error)) { fprintf(stderr, "routes: %s\n", error); t->failed = 1; return 0; }
                    t->routes = 1;
                }
                t->active = 1;
                printf("READY %s mtu=%u local_offer=%u peer_offer=%u\n", xdtls_suite(t->dtls),
                       selected, t->mtu_offer, t->peer_offer); fflush(stdout);
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
    /* Also cancel a wakeup armed by the best-effort close_notify. */
    (void)xudp_wait_writable(t->udp, false);
    t->count = t->head = 0; t->active = t->pong = 0;
    t->mtu_offer = t->peer_offer = t->mtu_selected = 0;
    if (t->cfg->mtu != XT_MTU) {
        char error[256];
        if (t->dev && !xt_device_set_mtu(t->dev, XT_MTU, error)) {
            fprintf(stderr, "MTU reset: %s\n", error); t->failed = 1;
        }
        t->cfg->mtu = XT_MTU;
    }
}
static void print_live_stats(Tunnel *t, uint64_t start) {
    xUdpStats udp = {0};
    xudp_get_stats(t->udp, &udp);
    XtDeviceStats dev = xt_device_stats(t->dev);
    printf("LIVE_STATS unix=%lld elapsed_ms=%llu active=%d "
           "udp_tx=%llu udp_rx=%llu udp_tx_bytes=%llu udp_rx_bytes=%llu "
           "udp_send_block=%llu udp_send_err=%llu udp_recv_err=%llu "
           "tun_tx_bytes=%llu tun_rx_bytes=%llu dtls_drop=%llu txq_drop=%llu "
           "peer_drop=%llu frame_drop=%llu ip_drop=%llu tun_write_drop=%llu "
           "win_oversize=%llu win_ring_full=%llu win_write_err=%llu\n",
           (long long)time(NULL), (unsigned long long)(t->now - start), t->active,
           (unsigned long long)udp.datagrams_sent, (unsigned long long)udp.datagrams_received,
           (unsigned long long)udp.bytes_sent, (unsigned long long)udp.bytes_received,
           (unsigned long long)udp.send_would_block, (unsigned long long)udp.send_errors,
           (unsigned long long)udp.receive_errors,
           (unsigned long long)t->rx_bytes, (unsigned long long)t->tx_bytes,
           (unsigned long long)t->drop_dtls_input, (unsigned long long)t->drop_tx_queue,
           (unsigned long long)t->drop_peer, (unsigned long long)t->drop_frame,
           (unsigned long long)t->drop_ip, (unsigned long long)t->drop_tun_write,
           (unsigned long long)dev.oversize,
           (unsigned long long)dev.write_ring_full, (unsigned long long)dev.write_error);
    fflush(stdout);
}
#ifndef _WIN32
static int run_hook(const char *name, const char *command, int stop_on_error) {
    if (!*command) return 1;
    char script[2056];
    snprintf(script, sizeof(script), "%s%s", stop_on_error ? "set -e\n" : "", command);
    int status = system(script);
    if (status != 0) fprintf(stderr, "%s failed (wait status %d)\n", name, status);
    return status == 0;
}
#endif
/* Returns the size the kernel actually granted, or 0 if it could not be read.
 * Best effort: buffer sizing is a performance choice, not a correctness one. */
static int udp_buffer_size(SOCKET_T fd, int option, int request) {
    int value = request;
#ifdef _WIN32
    int len = sizeof(value);
#else
    socklen_t len = sizeof(value);
#endif
    if (setsockopt(fd, SOL_SOCKET, option, (const char*)&value, sizeof(value)) != 0) return 0;
    if (getsockopt(fd, SOL_SOCKET, option, (char*)&value, &len) != 0) return 0;
    return value;
}
int xt_run(const XtConfig *cfg) {
    XtConfig effective = *cfg; effective.mtu = XT_MTU;
    cfg = &effective;
    Tunnel *t = calloc(1, sizeof(*t));
    if (!t) return 1;
    t->cfg = &effective; t->now = xt_now();
    uint64_t start = t->now, retry_at = start;
    uint64_t stats_period = (uint64_t)cfg->stats_interval * 1000;
    uint64_t next_stats = start + stats_period;
    char error[256]; int rc = 1;
    int tun_watched = 0;
#ifndef _WIN32
    int hooks_started = 0;
#endif
    xt_install_signals();
    xt_time_begin();
    if (socket_init() || xpoll_init()) goto done;
    xUdpConfig udp_cfg = {0}; udp_cfg.max_datagram = XDTLS_MAX_RECORD;
    /* Never drain more records per poll than an empty DTLS queue can hold. */
    udp_cfg.recv_budget = XDTLS_RX_SLOTS;
    udp_cfg.on_datagram = udp_receive; udp_cfg.on_error = udp_error; udp_cfg.userdata = t;
    t->udp = xudp_bind(cfg->bind_ip, cfg->bind_port, &udp_cfg, error);
    if (!t->udp) { fprintf(stderr, "UDP bind: %s\n", error); goto done; }
    int rcvbuf = udp_buffer_size(xudp_fd(t->udp), SO_RCVBUF, XT_UDP_BUFFER);
    int sndbuf = udp_buffer_size(xudp_fd(t->udp), SO_SNDBUF, XT_UDP_BUFFER);
    if (!cfg->server && xudp_address(cfg->remote_ip, (int)cfg->port, &t->peer)) goto done;
    if (!cfg->probe) {
        t->dev = xt_device_open(cfg, error);
        if (!t->dev) { fprintf(stderr, "virtual adapter: %s\n", error); goto done; }
#ifndef _WIN32
        if (cfg->server) {
            hooks_started = 1;
            if (!run_hook("PostUp", cfg->post_up, 1)) goto done;
        }
#endif
    }
    xUdpAddress bound; xudp_sockname(t->udp, &bound);
    printf("LISTEN %s:%u mode=%s%s udp_rcvbuf=%d udp_sndbuf=%d\n", bound.ip, bound.port,
           cfg->server ? "server" : "client", cfg->probe ? " probe" : "", rcvbuf, sndbuf); fflush(stdout);
    while (!xt_stop && !t->failed) {
        unsigned packets_read = 0;
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
                if (!t->mtu_offer) {
                    size_t payload = xdtls_max_payload(t->dtls);
                    t->mtu_offer = xt_mtu_offer(payload, cfg->mtu_limit);
                    printf("MTU_OFFER dtls_payload=%zu header=%d ceiling=%u offer=%u\n",
                           payload, XT_HEADER, cfg->mtu_limit, t->mtu_offer); fflush(stdout);
                    if (!t->mtu_offer) { fputs("DTLS payload too small for inner MTU\n", stderr); t->failed = 1; break; }
                }
                if (!t->active && t->now-t->last_ready >= 1000) queue_ready(t);
                /* Complete only the pending write before RX; submitting a new
                 * write here could block RX again even after recovery. */
                if ((xdtls_write_pending(t->dtls) && !flush(t, 1)) || !receive_messages(t)) { reset(t); retry_at = t->now+1000; }
                else {
                    if (t->active && t->now-t->last_ping >= (cfg->probe ? 1000u : 20000u)) {
                        unsigned char stamp[8]; put32(stamp, (uint32_t)(t->now>>32)); put32(stamp+4, (uint32_t)t->now);
                        if (enqueue(t, PING, stamp, 8)) t->last_ping = t->now;
                    }
                    if (t->active && !cfg->probe) {
                        unsigned char packet[65536];
                        while (packets_read < XT_READ_BUDGET && t->count < XT_QUEUE-4) {
                            int n = xt_device_read(t->dev, packet, sizeof(packet));
                            if (n < 0) { t->failed = 1; break; }
                            if (!n) break;
                            ++packets_read;
                            if (xt_packet_valid(cfg, packet, (size_t)n, 0)) enqueue(t, DATA, packet, (size_t)n);
                            else { ++t->drops; ++t->drop_ip; }
                        }
                    }
                    if (!flush(t, XT_QUEUE)) { reset(t); retry_at = t->now+1000; }
                }
            }
        }
        if (stats_period && t->now >= next_stats) {
            print_live_stats(t, start);
            next_stats = t->now + stats_period;
        }
        if (cfg->probe && !cfg->server && t->probe_ok) { rc = 0; break; }
        /* Like the TUN backlog, leave UDP backlog upstream until there is
         * room. Reset sessions must also restore the listener. */
        if ((!t->dtls || xdtls_input_space(t->dtls)) && xudp_resume_read(t->udp) != XUDP_OK) {
            fputs("cannot resume UDP reads\n", stderr);
            t->failed = 1;
            break;
        }
        int can_read_tun = t->dev && t->active && t->count < XT_QUEUE-4;
        /* Read TUN in the main loop. Poll only needs to wake it, and
         * watching a readable TUN while backpressured would spin. */
        if (can_read_tun && !tun_watched) {
            if (xpoll_add_event(xt_device_fd(t->dev), XPOLL_READABLE, NULL, NULL, NULL, NULL)) {
                fputs("cannot watch TUN readiness\n", stderr);
                t->failed = 1;
                break;
            }
            tun_watched = 1;
        } else if (!can_read_tun && tun_watched) {
            xpoll_del_event(xt_device_fd(t->dev), XPOLL_READABLE);
            tun_watched = 0;
        }
        xpoll_poll(can_read_tun && packets_read == XT_READ_BUDGET ? 0 : 5);
    }
    if (xt_stop) rc = 0;
    if (t->failed) rc = 1;
done:
    ;
    XtDeviceStats dev = xt_device_stats(t->dev);
    uint64_t device_drops = dev.oversize;
    printf("STATS tx_packets=%llu rx_packets=%llu tx_bytes=%llu rx_bytes=%llu drops=%llu "
        "drop_peer=%llu drop_dtls_input=%llu drop_tx_queue=%llu drop_frame=%llu "
        "drop_ip=%llu drop_tun_write=%llu drop_device=%llu\n",
        (unsigned long long)t->tx_packets, (unsigned long long)t->rx_packets,
        (unsigned long long)t->tx_bytes, (unsigned long long)t->rx_bytes,
        (unsigned long long)(t->drops + device_drops),
        (unsigned long long)t->drop_peer, (unsigned long long)t->drop_dtls_input,
        (unsigned long long)t->drop_tx_queue, (unsigned long long)t->drop_frame,
        (unsigned long long)t->drop_ip, (unsigned long long)t->drop_tun_write,
        (unsigned long long)device_drops);
    xUdpStats udp_stats = {0};
    if (t->udp) xudp_get_stats(t->udp, &udp_stats);
    printf("UDP_STATS rx_datagrams=%llu tx_datagrams=%llu rx_oversize=%llu "
        "receive_errors=%llu send_errors=%llu send_would_block=%llu\n",
        (unsigned long long)udp_stats.datagrams_received, (unsigned long long)udp_stats.datagrams_sent,
        (unsigned long long)udp_stats.dropped_oversize, (unsigned long long)udp_stats.receive_errors,
        (unsigned long long)udp_stats.send_errors, (unsigned long long)udp_stats.send_would_block);
    if (xdtls_ready(t->dtls) && t->active && !t->count) {
        enqueue(t, CLOSE, NULL, 0); (void)flush(t, XT_QUEUE);
    }
    if (tun_watched) xpoll_del_event(xt_device_fd(t->dev), XPOLL_READABLE);
#ifndef _WIN32
    if (hooks_started && !run_hook("PostDown", cfg->post_down, 0)) rc = 1;
#endif
    reset(t); xt_device_close(t->dev); xudp_destroy(t->udp); xpoll_uninit(); socket_cleanup();
    xt_time_end();
    free(t); return rc;
}
