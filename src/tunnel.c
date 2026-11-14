#include "xtun.h"
#include "xdtls.h"
#include "xudp.h"
#include "xpoll.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#define XT_QUEUE 64
#define XT_READ_BUDGET 32
/* Linux clamps SO_RCVBUF/SO_SNDBUF to 2x rmem_max and ignores the rest. */
#define XT_UDP_BUFFER (4*1024*1024)
enum { READY = 1, DATA, PING, PONG, CLOSE, ARQ_DATA, ARQ_NACK, ARQ_MARK };
#define ARQ_WINDOW 1024u
#define ARQ_TTL 1000u
#define ARQ_INITIAL 20u
#define ARQ_BACKOFF_MAX 160u
#define ARQ_RESEND_GAP 100u
#define ARQ_MARK_INTERVAL 200u
#define ARQ_BATCH 512u /* 1024-byte feedback payload fits even the minimum MTU */
typedef struct {
    uint32_t seq;
    uint64_t born;
    int received, expired, requested, gap;
} ArqRx;
typedef struct {
    uint32_t seq;
    uint64_t born, retry_at;
    unsigned retries, queued;
    size_t len;
    unsigned char bytes[2 + XT_MTU_MAX];
} ArqTx;
typedef struct {
    uint32_t next, sent, high;
    uint64_t last_data, last_mark, nack_due;
    unsigned missing, delay, cursor;
    int timer, timer_logged, nack_queued, mark_queued;
    size_t credit;
    ArqRx rx[ARQ_WINDOW];
    ArqTx tx[ARQ_WINDOW];
} Arq;
volatile sig_atomic_t xt_stop;

static uint32_t be32(const unsigned char *p) { return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; }
static void put32(unsigned char *p, uint32_t n) { p[0]=n>>24; p[1]=n>>16; p[2]=n>>8; p[3]=n; }
static uint16_t be16(const unsigned char *p) { return (uint16_t)((unsigned)p[0]<<8 | p[1]); }
static void put16(unsigned char *p, uint16_t n) { p[0]=(unsigned char)(n>>8); p[1]=(unsigned char)n; }
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
    unsigned peer_arq;
    Arq *arq;
    uint64_t arq_nacks, arq_requests, arq_retransmits, arq_recovered, arq_duplicates;
    uint64_t arq_expired, arq_cache_miss, arq_limited;
    struct { size_t len; uint64_t expires; int retry; unsigned char bytes[XT_HEADER + 2 + XT_MTU_MAX]; } queue[XT_QUEUE];
    int active, routes, failed, probe_ok, pong;
} Tunnel;
static void arq_log(Tunnel *t, const char *event, const char *format, ...) {
    if (!t->cfg->arq_log) return;
    printf("ARQ_EVENT unix=%lld mono_ms=%llu side=%s session=%llu event=%s ",
           (long long)time(NULL), (unsigned long long)t->now,
           t->cfg->server ? "server" : "client", (unsigned long long)t->born, event);
    va_list args; va_start(args, format); vprintf(format, args); va_end(args);
    putchar('\n'); fflush(stdout);
}
static void arq_log_batch(Tunnel *t, const char *event, const unsigned char *seqs, unsigned count) {
    if (!t->cfg->arq_log) return;
    char list[16*6+1]; size_t used=0;
    unsigned shown=count<16 ? count : 16;
    list[0]=0;
    for (unsigned i=0; i<shown; ++i)
        used+=(size_t)snprintf(list+used, sizeof(list)-used, "%s%u", i ? "," : "", be16(seqs+2*i));
    arq_log(t,event,"count=%u seqs=%s omitted=%u missing=%u", count,list,count-shown,t->arq->missing);
}
static void arq_timer_cancel(Tunnel *t, const char *reason) {
    Arq *a=t->arq;
    if (a->timer) arq_log(t,"timer_cancel","reason=%s missing=%u",reason,a->missing);
    a->timer=0; a->timer_logged=0;
}
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
    int original = type == DATA && t->arq;
    int is_data = type == DATA || type == ARQ_DATA;
    /* Reserve four slots for control. All buffers have fixed byte bounds. */
    if (n > (type == ARQ_DATA ? XT_MTU_MAX+2 : XT_MTU_MAX) || (type == DATA && n > t->cfg->mtu) ||
        t->count >= (is_data ? XT_QUEUE-4 : XT_QUEUE)) { ++t->drops; ++t->drop_tx_queue; return 0; }
    unsigned tail = (t->head + t->count) % XT_QUEUE;
    unsigned char *p = t->queue[tail].bytes;
    p[0] = 1; p[1] = (unsigned char)(original ? ARQ_DATA : type); p[2] = p[3] = 0;
    put32(p+4, (uint32_t)n + (original ? 2 : 0));
    if (original) put16(p+8, (uint16_t)++t->arq->next);
    if (n) memcpy(p+8+(original ? 2 : 0), data, n);
    t->queue[tail].len = XT_HEADER + n + (original ? 2 : 0);
    t->queue[tail].retry = 0; t->queue[tail].expires = 0;
    ++t->count; return 1;
}
static void queue_ready(Tunnel *t) {
    unsigned char p[16] = {0}; put32(p, t->cfg->address); put32(p+4, t->cfg->peer_address);
    p[8] = t->mtu_offer >> 8; p[9] = t->mtu_offer & 255;
    p[10] = t->mtu_selected >> 8; p[11] = t->mtu_selected & 255;
    p[12] = 1; /* MTU negotiation version; selected=0 until peer offer arrives */
    p[13] = (unsigned char)t->cfg->arq;
    p[14] = (unsigned char)(t->cfg->arq && t->peer_arq);
    if (enqueue(t, READY, p, sizeof(p))) t->last_ready = t->now;
}
static unsigned arq_feedback(Tunnel *t, unsigned char *out) {
    Arq *a = t->arq; unsigned count = 0, expired = 0;
    for (unsigned j = 0; j < ARQ_WINDOW; ++j) {
        ArqRx *r = &a->rx[(a->cursor+j)%ARQ_WINDOW];
        if (!r->seq || r->received || r->expired) continue;
        if (t->now-r->born >= ARQ_TTL) { r->expired=1; --a->missing; ++t->arq_expired; ++expired; continue; }
        put16(out+2*count, (uint16_t)r->seq);
        if (++count == ARQ_BATCH) break;
    }
    if (expired) arq_log(t,"gap_expired","reason=ttl count=%u missing=%u",expired,a->missing);
    if (!a->missing) arq_timer_cancel(t,"expired");
    return count;
}
static void arq_pop(Tunnel *t) {
    t->head = (t->head+1)%XT_QUEUE; --t->count;
}
static int flush(Tunnel *t, unsigned budget) {
    for (unsigned i = 0; i < budget && t->count; ++i) {
        unsigned head = t->head; size_t n = t->queue[head].len;
        unsigned char *p = t->queue[head].bytes;
        /* Refresh/cancel queued feedback only before a DTLS write starts.
         * WANT_WRITE requires an immutable retry of the exact same message. */
        if (p[1] == ARQ_NACK && !xdtls_write_pending(t->dtls)) {
            unsigned count = arq_feedback(t, p+XT_HEADER);
            if (!count) {
                arq_log(t,"nack_cancel","reason=no_gaps");
                t->arq->nack_queued=0; arq_pop(t); continue;
            }
            put32(p+4, count*2); n = t->queue[head].len = XT_HEADER+count*2;
        }
        if (p[1] == ARQ_MARK && !xdtls_write_pending(t->dtls)) {
            if (t->now-t->arq->last_data >= ARQ_TTL) { t->arq->mark_queued=0; arq_pop(t); continue; }
            put16(p+XT_HEADER, (uint16_t)t->arq->sent);
        }
        if (t->queue[head].retry && t->now >= t->queue[head].expires && !xdtls_write_pending(t->dtls)) {
            uint16_t seq = be16(p+XT_HEADER);
            ArqTx *cached = &t->arq->tx[seq % ARQ_WINDOW];
            if ((uint16_t)cached->seq == seq) cached->queued = 0;
            arq_log(t,"repair_drop","seq=%u reason=expired late_ms=%llu",seq,
                    (unsigned long long)(t->now-t->queue[head].expires));
            t->arq->credit += n;
            if (t->arq->credit > 32*XT_MTU_MAX) t->arq->credit = 32*XT_MTU_MAX;
            arq_pop(t); continue;
        }
        int rc = xdtls_write(t->dtls, t->queue[head].bytes, n);
        if (rc == XDTLS_AGAIN) return 1;
        if (rc != (int)n) return 0;
        if (t->queue[head].bytes[1] == DATA) { ++t->tx_packets; t->tx_bytes += n-XT_HEADER; }
        if (t->queue[head].bytes[1] == ARQ_DATA) {
            Arq *a = t->arq;
            uint16_t seq = be16(p+XT_HEADER);
            ArqTx *cached = &a->tx[seq % ARQ_WINDOW];
            if (t->queue[head].retry) {
                ++t->arq_retransmits;
                if ((uint16_t)cached->seq == seq) { cached->queued = 0; ++cached->retries; cached->retry_at = t->now+ARQ_RESEND_GAP; }
                arq_log(t,"repair_sent","seq=%u retry=%u age_ms=%llu bytes=%zu",seq,cached->retries,
                        (unsigned long long)(t->now-cached->born),n);
            } else {
                ++t->tx_packets; t->tx_bytes += n-XT_HEADER-2;
                if (!a->sent) a->last_mark = t->now;
                ++a->sent; cached->seq = a->sent; cached->born = t->now; cached->retry_at = 0;
                cached->retries = cached->queued = 0; cached->len = n-XT_HEADER;
                memcpy(cached->bytes, t->queue[head].bytes+XT_HEADER, cached->len);
                a->last_data = t->now;
                a->credit += n/4; /* at most 25% extra bytes plus a small burst */
                if (a->credit > 32*XT_MTU_MAX) a->credit = 32*XT_MTU_MAX;
            }
        }
        if (p[1] == ARQ_NACK) {
            Arq *a = t->arq; ++t->arq_nacks; a->nack_queued=0;
            arq_log_batch(t,"nack_sent",p+XT_HEADER,(unsigned)((n-XT_HEADER)/2));
            for (size_t j = XT_HEADER; j < n; j += 2) {
                uint16_t seq = be16(p+j); ArqRx *r = &a->rx[seq%ARQ_WINDOW];
                if (r->seq && (uint16_t)r->seq == seq) r->requested=1;
                a->cursor=(seq+1u)%ARQ_WINDOW;
            }
            a->nack_due=t->now+a->delay;
            a->timer_logged=0;
            if (a->timer) arq_log(t,"timer_arm","delay_ms=%u due_ms=%llu missing=%u",a->delay,
                                 (unsigned long long)a->nack_due,a->missing);
            if (a->delay < ARQ_BACKOFF_MAX) a->delay *= 2;
        }
        if (p[1] == ARQ_MARK) {
            arq_log(t,"mark_sent","seq=%u",be16(p+XT_HEADER));
            t->arq->mark_queued=0; t->arq->last_mark=t->now;
        }
        ++t->records; t->last_tx = t->now;
        arq_pop(t);
    }
    return 1;
}
/* No delivery queue: received packets can pass immediately, even with gaps. */
static int arq_advance(Tunnel *t, uint16_t wire, uint32_t *logical, int watermark) {
    Arq *a = t->arq;
    unsigned delta = (uint16_t)(wire-(uint16_t)a->high);
    if (delta && delta < 32768) {
        /* Beyond the bounded window we cannot repair/interpret a blackout
         * safely. A new DTLS session resets both directions and rejects old data. */
        if (delta >= ARQ_WINDOW) return -1;
        uint32_t seq = a->high+delta, previous=a->high;
        unsigned evicted=0;
        for (uint32_t i = a->high+1; i <= seq; ++i) {
            ArqRx *r = &a->rx[i % ARQ_WINDOW];
            if (r->seq && !r->received && !r->expired) { --a->missing; ++t->arq_expired; ++evicted; }
            *r = (ArqRx){.seq=i, .born=t->now, .gap=watermark || i<seq}; ++a->missing;
        }
        a->high = seq;
        if (evicted) arq_log(t,"gap_expired","reason=window_evicted count=%u missing=%u",evicted,a->missing);
        unsigned gaps=delta-(watermark ? 0 : 1);
        if (gaps) arq_log(t,"gap_detect","trigger=%s first=%u last=%u count=%u logical_first=%u",
                          watermark ? "watermark" : "data",(uint16_t)(previous+1),
                          (uint16_t)(previous+gaps),gaps,previous+1);
        *logical=seq; return 1;
    }
    unsigned back = (uint16_t)((uint16_t)a->high-wire);
    if (back >= ARQ_WINDOW) return -1;
    if (back >= a->high) return 0;
    *logical=a->high-back;
    return a->rx[*logical%ARQ_WINDOW].seq == *logical;
}
static int arq_receive(Tunnel *t, uint16_t wire, int delivered) {
    uint32_t seq; int rc = arq_advance(t, wire, &seq, 0);
    if (rc <= 0) return rc;
    ArqRx *r = &t->arq->rx[seq % ARQ_WINDOW];
    if (r->received) { ++t->arq_duplicates; arq_log(t,"duplicate","seq=%u logical_seq=%u",wire,seq); return 0; }
    if (delivered) {
        if (r->requested) ++t->arq_recovered; /* gap filled, possibly by a late original */
        r->received = 1;
        if (!r->expired) --t->arq->missing;
        if (r->gap || r->requested) arq_log(t,"gap_filled","seq=%u logical_seq=%u requested=%d age_ms=%llu missing=%u",
                                          wire,seq,r->requested,(unsigned long long)(t->now-r->born),t->arq->missing);
        if (!t->arq->missing) arq_timer_cancel(t,"gap_filled");
    }
    return 1;
}
static void arq_request(Tunnel *t, uint16_t seq) {
    ArqTx *c = &t->arq->tx[seq % ARQ_WINDOW];
    if (!c->seq || (uint16_t)c->seq != seq || t->now-c->born >= ARQ_TTL) {
        ++t->arq_cache_miss; arq_log(t,"repair_skip","seq=%u reason=cache_miss_or_expired",seq); return;
    }
    if (c->queued || c->retries >= 2 || t->now < c->retry_at) {
        arq_log(t,"repair_skip","seq=%u reason=%s",seq,c->queued ? "already_queued" : c->retries>=2 ? "retry_limit" : "cooldown"); return;
    }
    if (t->count >= XT_QUEUE-4) { arq_log(t,"repair_skip","seq=%u reason=queue_full",seq); return; }
    size_t cost = XT_HEADER+c->len;
    if (t->arq->credit < cost) { ++t->arq_limited; arq_log(t,"repair_skip","seq=%u reason=budget",seq); return; }
    unsigned tail = (t->head+t->count) % XT_QUEUE;
    if (!enqueue(t, ARQ_DATA, c->bytes, c->len)) return;
    t->queue[tail].retry = 1; t->queue[tail].expires = c->born+ARQ_TTL;
    c->queued = 1; t->arq->credit -= cost;
    arq_log(t,"repair_queued","seq=%u retry=%u bytes=%zu",seq,c->retries+1,cost);
}
static void arq_tick(Tunnel *t) {
    Arq *a = t->arq;
    if (!a) return;
    if (a->sent && !a->mark_queued && t->now-a->last_data < ARQ_TTL &&
        t->now-a->last_mark >= ARQ_MARK_INTERVAL && t->count < XT_QUEUE-2) {
        unsigned char mark[2]; put16(mark, (uint16_t)a->sent);
        if (enqueue(t, ARQ_MARK, mark, sizeof(mark))) a->mark_queued=1;
    }
    if (!a->missing) { arq_timer_cancel(t,"no_gaps"); return; }
    if (!a->timer) {
        a->timer=1; a->timer_logged=0; a->delay=ARQ_INITIAL; a->nack_due=t->now;
        arq_log(t,"timer_start","due_ms=%llu missing=%u",(unsigned long long)a->nack_due,a->missing);
    }
    if (t->now >= a->nack_due && !a->timer_logged) {
        arq_log(t,"timer_expire","due_ms=%llu late_ms=%llu missing=%u queue=%u",
                (unsigned long long)a->nack_due,(unsigned long long)(t->now-a->nack_due),a->missing,t->count);
        a->timer_logged=1;
    }
    if (a->nack_queued || t->now < a->nack_due || t->count >= XT_QUEUE-2) return;
    unsigned char placeholder[2] = {0};
    if (enqueue(t, ARQ_NACK, placeholder, sizeof(placeholder))) {
        a->nack_queued=1;
    }
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
                p[20] != 1 || p[21] > 1 || p[22] > 1 || p[23]) {
                fputs("peer tunnel parameters mismatch\n", stderr); return 0;
            }
            unsigned offer = (unsigned)p[16]<<8 | p[17];
            unsigned confirmed = (unsigned)p[18]<<8 | p[19];
            unsigned selected = offer < t->mtu_offer ? offer : t->mtu_offer;
            unsigned arq = t->cfg->arq && p[21];
            if (offer < XT_MTU || offer > XT_MTU_MAX ||
                (t->peer_offer && (offer != t->peer_offer || t->peer_arq != p[21])) ||
                (confirmed && (confirmed != selected || p[22] != arq)) || (!confirmed && p[22])) {
                fputs("peer MTU negotiation mismatch\n", stderr); return 0;
            }
            t->peer_offer = offer; t->mtu_selected = selected; t->peer_arq = p[21];
            t->last_rx = t->now;
            if (t->now - t->last_ready >= 500 || !t->active) queue_ready(t);
            if (!t->active && confirmed) {
                char error[256];
                if (arq) {
                    t->arq = calloc(1, sizeof(*t->arq));
                    if (!t->arq) { t->failed = 1; return 0; }
                    t->arq->credit = 4*XT_MTU_MAX;
                }
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
                arq_log(t,"session_ready","enabled=%u mtu=%u",arq,selected);
                printf("READY %s mtu=%u local_offer=%u peer_offer=%u arq=%u\n", xdtls_suite(t->dtls),
                       selected, t->mtu_offer, t->peer_offer, arq); fflush(stdout);
            }
        } else if ((p[1] == DATA || p[1] == ARQ_DATA) && t->active && !t->cfg->probe) {
            int sequenced = p[1] == ARQ_DATA;
            if (sequenced != !!t->arq || (sequenced && n < 2)) {
                ++t->drops; ++t->drop_frame; continue;
            }
            unsigned char *ip = p+8+(sequenced ? 2 : 0);
            size_t ip_len = n-(sequenced ? 2 : 0);
            if (!xt_packet_valid(t->cfg, ip, ip_len, 1)) { ++t->drops; ++t->drop_ip; continue; }
            t->last_rx = t->now;
            if (sequenced) {
                int accepted = arq_receive(t, be16(p+8), 0);
                if (accepted < 0) {
                    arq_log(t,"resync","trigger=data seq=%u high=%u",be16(p+8),(uint16_t)t->arq->high);
                    fputs("ARQ sequence outside receive window; resync\n", stderr); return 0;
                }
                if (!accepted) continue;
            }
            if (xt_device_write(t->dev, ip, ip_len) > 0) {
                ++t->rx_packets; t->rx_bytes += ip_len;
                if (sequenced) arq_receive(t, be16(p+8), 1);
            }
            else {
                ++t->drops; ++t->drop_tun_write;
                if (sequenced) {
                    t->arq->rx[be16(p+8)%ARQ_WINDOW].gap=1;
                    arq_log(t,"delivery_failed","seq=%u reason=tun_write",be16(p+8));
                }
            }
        } else if (p[1] == ARQ_NACK && t->active && t->arq && n && n <= 2*ARQ_BATCH && !(n%2)) {
            t->last_rx = t->now;
            arq_log_batch(t,"nack_received",p+8,(unsigned)(n/2));
            for (size_t j = 0; j < n; j += 2) { ++t->arq_requests; arq_request(t, be16(p+8+j)); }
        } else if (p[1] == ARQ_MARK && t->active && t->arq && n == 2) {
            uint32_t seq;
            t->last_rx = t->now;
            arq_log(t,"mark_received","seq=%u high=%u",be16(p+8),(uint16_t)t->arq->high);
            if (arq_advance(t, be16(p+8), &seq, 1) < 0) {
                arq_log(t,"resync","trigger=watermark seq=%u high=%u",be16(p+8),(uint16_t)t->arq->high);
                fputs("ARQ watermark outside receive window; resync\n", stderr); return 0;
            }
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
    if (t->arq) {
        arq_timer_cancel(t,"session_clear");
        arq_log(t,"session_clear","missing=%u queued=%u",t->arq->missing,t->count);
    }
    xdtls_close(t->dtls); xdtls_destroy(t->dtls); t->dtls = NULL;
    /* Also cancel a wakeup armed by the best-effort close_notify. */
    (void)xudp_wait_writable(t->udp, false);
    t->count = t->head = 0; t->active = t->pong = 0;
    t->mtu_offer = t->peer_offer = t->mtu_selected = 0;
    t->peer_arq = 0; free(t->arq); t->arq = NULL;
    if (t->cfg->mtu != XT_MTU) {
        char error[256];
        if (t->dev && !xt_device_set_mtu(t->dev, XT_MTU, error)) {
            fprintf(stderr, "MTU reset: %s\n", error); t->failed = 1;
        }
        t->cfg->mtu = XT_MTU;
    }
}
static void print_arq_stats(Tunnel *t) {
    printf("ARQ_STATS enabled=%d nack_packets=%llu requested=%llu retransmits=%llu "
           "gap_filled=%llu duplicates=%llu expired=%llu cache_miss=%llu limited=%llu\n",
           t->arq != NULL, (unsigned long long)t->arq_nacks, (unsigned long long)t->arq_requests,
           (unsigned long long)t->arq_retransmits, (unsigned long long)t->arq_recovered,
           (unsigned long long)t->arq_duplicates, (unsigned long long)t->arq_expired,
           (unsigned long long)t->arq_cache_miss, (unsigned long long)t->arq_limited);
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
    print_arq_stats(t); fflush(stdout);
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
                    t->mtu_offer = xt_mtu_offer(payload >= 2 && cfg->arq ? payload-2 : payload, cfg->mtu_limit);
                    printf("MTU_OFFER dtls_payload=%zu header=%d ceiling=%u offer=%u\n",
                           payload, XT_HEADER+(cfg->arq ? 2 : 0), cfg->mtu_limit, t->mtu_offer); fflush(stdout);
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
                    if (t->active) arq_tick(t);
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
    print_arq_stats(t);
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
