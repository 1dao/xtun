#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xdtls.h"
#include "xudp.h"
#include "xpoll.h"
#include "xtun.h"
#include "../core/3rd/mbedtls3/library/ssl_misc.h"
#ifndef MBEDTLS_SSL_DTLS_REPLAY_WINDOW
#define MBEDTLS_SSL_DTLS_REPLAY_WINDOW 64 /* upstream fixed replay window */
#endif

typedef struct End {
    xDtls *dtls;
    struct End *peer;
    int drop, block, hold;
    unsigned char saved[XDTLS_MAX_RECORD];
    size_t saved_len;
    unsigned sent;
    xUdp *udp;
    xUdp *write_wait;
    xUdpAddress destination;
} End;
static int transport(void *p, const unsigned char *data, size_t n) {
    End *e = p;
    if (e->block) {
        --e->block;
        if (e->write_wait) assert(!xudp_wait_writable(e->write_wait, true));
        return XDTLS_AGAIN;
    }
    if (e->write_wait) assert(!xudp_wait_writable(e->write_wait, false));
    ++e->sent;
    memcpy(e->saved, data, n); e->saved_len = n;
    if (e->udp) {
        int error;
        return xudp_sendto(e->udp, data, n, &e->destination, &error) == XUDP_OK ? (int)n : XDTLS_ERROR;
    }
    if (e->drop) { --e->drop; return (int)n; }
    if (!e->hold) assert(xdtls_feed(e->peer->dtls, data, n) == 0);
    return (int)n;
}
static void pair(End *a, End *b, int wrong_key, int wrong_id) {
    unsigned char ka[32], kb[32];
    memset(ka, 0x37, 32); memcpy(kb, ka, 32); kb[0] ^= !!wrong_key;
    memset(a, 0, sizeof(*a)); memset(b, 0, sizeof(*b)); a->peer = b; b->peer = a;
    char error[256];
    xDtlsConfig c = {0};
    c.psk = ka; c.identity = wrong_id ? "wrong" : "test-peer";
    c.send = transport; c.userdata = a;
    a->dtls = xdtls_create(&c, error);
    if (!a->dtls) { fprintf(stderr, "client create: %s\n", error); abort(); }
    c.server = 1; c.psk = kb; c.identity = "test-peer"; c.userdata = b;
    c.transport_id = "127.0.0.1:12345"; c.transport_id_len = strlen(c.transport_id);
    b->dtls = xdtls_create(&c, error);
    if (!b->dtls) { fprintf(stderr, "server create: %s\n", error); abort(); }
}
static int handshake(End *a, End *b) {
    for (uint64_t now = 0; now < 20000; now += 10) {
        if (xdtls_step(a->dtls, now) < 0 || xdtls_step(b->dtls, now) < 0) return 0;
        if (xdtls_ready(a->dtls) && xdtls_ready(b->dtls)) return 1;
    }
    return 0;
}
static void destroy(End *a, End *b) { xdtls_destroy(a->dtls); xdtls_destroy(b->dtls); }
static void channel_tests(void) {
    End a, b;
    unsigned char buf[2048];
    const unsigned char message[] = {0, 255, 1, 2, 0, 4};
    pair(&a, &b, 0, 0);
    a.drop = 1; b.drop = 1;
    assert(handshake(&a, &b));
    assert(strstr(xdtls_suite(a.dtls), "ECDHE-PSK-WITH-CHACHA20-POLY1305"));
    assert(xdtls_max_payload(a.dtls) > 1288);
    unsigned mtu = xt_mtu_offer(xdtls_max_payload(a.dtls), 0);
    assert(mtu > XT_MTU && mtu <= XT_MTU_MAX);
    assert(xt_mtu_offer(XT_HEADER + XT_MTU - 1, 0) == 0);
    assert(xt_mtu_offer(4096, 0) == XT_MTU_MAX);
    assert(xt_mtu_offer(xdtls_max_payload(a.dtls), 1300) == 1300);
    memset(buf, 0xa5, mtu + XT_HEADER);
    assert(xdtls_write(a.dtls, buf, mtu + XT_HEADER) == (int)(mtu + XT_HEADER));
    assert(a.saved_len <= 1400);
    assert(xdtls_read(b.dtls, buf, sizeof(buf)) == (int)(mtu + XT_HEADER));
    for (unsigned i = 0; i < mtu + XT_HEADER; ++i) assert(buf[i] == 0xa5);
    printf("PASS DTLS-derived inner MTU=%u fits a single record\n", mtu);
    printf("PASS handshake survives initial packet loss; suite=%s\n", xdtls_suite(a.dtls));
    a.block = 1;
    assert(xdtls_write(a.dtls, message, sizeof(message)) == XDTLS_AGAIN);
    assert(xdtls_write(a.dtls, message, sizeof(message)) == sizeof(message));
    assert(xdtls_read(b.dtls, buf, sizeof(buf)) == sizeof(message));
    assert(!memcmp(message, buf, sizeof(message)));
    puts("PASS binary datagrams and send backpressure");
    a.block = 3;
    assert(xdtls_write(a.dtls, "interleave", 10) == XDTLS_AGAIN);
    unsigned before_retry = a.sent;
    assert(xdtls_read(a.dtls, buf, sizeof(buf)) == XDTLS_AGAIN);
    assert(a.sent == before_retry);
    assert(xdtls_write(a.dtls, "interleave", 10) == XDTLS_AGAIN);
    assert(xdtls_read(a.dtls, buf, sizeof(buf)) == XDTLS_AGAIN);
    assert(xdtls_write(a.dtls, "interleave", 10) == XDTLS_AGAIN);
    assert(xdtls_read(a.dtls, buf, sizeof(buf)) == XDTLS_AGAIN);
    assert(xdtls_write(a.dtls, "interleave", 10) == 10);
    assert(xdtls_read(b.dtls, buf, sizeof(buf)) == 10 && !memcmp(buf, "interleave", 10));
    int extra = xdtls_read(b.dtls, buf, sizeof(buf));
    if (extra != XDTLS_AGAIN) fprintf(stderr, "Unexpected duplicate after read/write interleaving: %d bytes\n", extra);
    assert(extra == XDTLS_AGAIN);
    puts("PASS write retry remains exactly once across interleaved reads");
    b.block = 1;
    assert(xdtls_write(b.dtls, "reverse", 7) == XDTLS_AGAIN);
    assert(xdtls_read(b.dtls, buf, sizeof(buf)) == XDTLS_AGAIN);
    assert(xdtls_write(b.dtls, "reverse", 7) == 7);
    assert(xdtls_read(a.dtls, buf, sizeof(buf)) == 7 && !memcmp(buf, "reverse", 7));
    assert(xdtls_read(a.dtls, buf, sizeof(buf)) == XDTLS_AGAIN);
    puts("PASS server write retries also remain exactly once");
    assert(xdtls_feed(b.dtls, a.saved, a.saved_len) == 0);
    assert(xdtls_read(b.dtls, buf, sizeof(buf)) == XDTLS_AGAIN);
    puts("PASS duplicate record rejected");
    a.hold = 1;
    assert(xdtls_write(a.dtls, "first", 5) == 5);
    unsigned char first[2048]; size_t first_len = a.saved_len;
    memcpy(first, a.saved, first_len);
    assert(xdtls_write(a.dtls, "second", 6) == 6);
    assert(xdtls_feed(b.dtls, a.saved, a.saved_len) == 0);
    assert(xdtls_feed(b.dtls, first, first_len) == 0);
    assert(xdtls_read(b.dtls, buf, sizeof(buf)) == 6 && !memcmp(buf, "second", 6));
    assert(xdtls_read(b.dtls, buf, sizeof(buf)) == 5 && !memcmp(buf, "first", 5));
    puts("PASS authenticated out-of-order datagrams accepted");
    assert(xdtls_write(a.dtls, "tamper", 6) == 6);
    a.saved[a.saved_len - 1] ^= 1;
    assert(xdtls_feed(b.dtls, a.saved, a.saved_len) == 0);
    assert(xdtls_read(b.dtls, buf, sizeof(buf)) == XDTLS_AGAIN);
    a.hold = 0;
    assert(xdtls_write(a.dtls, "after", 5) == 5);
    assert(xdtls_read(b.dtls, buf, sizeof(buf)) == 5 && !memcmp(buf, "after", 5));
    puts("PASS tampering rejected without destroying healthy session");
    assert(xdtls_write(b.dtls, message, sizeof(message)) == sizeof(message));
    assert(xdtls_read(a.dtls, buf, sizeof(buf)) == sizeof(message));
    assert(!memcmp(message, buf, sizeof(message)));
    xdtls_close(a.dtls);
    assert(xdtls_read(b.dtls, buf, sizeof(buf)) == XDTLS_ERROR);
    assert(xdtls_closed(b.dtls));
    puts("PASS reverse direction and authenticated close");
    destroy(&a, &b);
    pair(&a, &b, 1, 0); assert(!handshake(&a, &b)); destroy(&a, &b);
    puts("PASS wrong PSK rejected");
    pair(&a, &b, 0, 1); assert(!handshake(&a, &b)); destroy(&a, &b);
    puts("PASS unknown identity rejected");
    pair(&a, &b, 0, 0); a.drop = 1000; assert(!handshake(&a, &b)); destroy(&a, &b);
    puts("PASS complete loss times out");
    pair(&a, &b, 0, 0);
    for (int i = 0; i < XDTLS_RX_SLOTS; ++i) assert(!xdtls_feed(b.dtls, "x", 1));
    assert(xdtls_feed(b.dtls, "x", 1) == XDTLS_ERROR);
    assert(xdtls_feed(a.dtls, buf, XDTLS_MAX_RECORD + 1) == XDTLS_ERROR);
    destroy(&a, &b);
    puts("PASS bounded receive queue and oversize rejection");
}
static int udp_received;
static void udp_receive(xUdp *u, const char *data, size_t n, const xUdpAddress *addr, void *p) {
    (void)u; (void)p;
    assert(n == 3 && !memcmp(data, "a\0b", 3));
    assert(addr->port && !strcmp(addr->ip, "127.0.0.1")); ++udp_received;
}
static void udp_test(void) {
    assert(!socket_init());
    assert(!xpoll_init());
    char error[XSOCK_ERR_LEN]; xUdpConfig cfg = {0}; cfg.on_datagram = udp_receive;
    xUdp *a = xudp_bind("127.0.0.1", 0, &cfg, error);
    xUdp *b = xudp_bind("127.0.0.1", 0, &cfg, error);
    assert(a && b); xUdpAddress addr; assert(!xudp_sockname(b, &addr));
    int sys; assert(!xudp_sendto(a, "a\0b", 3, &addr, &sys));
    for (int i = 0; i < 100 && !udp_received; ++i) xpoll_poll(5);
    assert(udp_received == 1);
    xudp_destroy(a); xudp_destroy(b);
    assert(!xudp_live_count() && !xudp_socket_count()); xpoll_uninit(); socket_cleanup();
    puts("PASS real UDP loopback and resource cleanup");
}
typedef struct { xDtls *dtls; unsigned received, rejected; } Input;
static void bounded_input(xUdp *u, const char *data, size_t n, const xUdpAddress *from, void *p) {
    Input *input = p;
    (void)from;
    ++input->received;
    if (xdtls_feed(input->dtls, data, n)) ++input->rejected;
    if (!xdtls_input_space(input->dtls)) xudp_pause_read(u);
}
static void duplex_backpressure_test(void) {
    End a, b;
    pair(&a, &b, 0, 0); assert(handshake(&a, &b));
    assert(!socket_init()); assert(!xpoll_init());
    Input input = {a.dtls, 0, 0};
    char error[XSOCK_ERR_LEN];
    xUdpConfig cfg = {0};
    /* Deliberately exceed the DTLS capacity within a single read callback. */
    cfg.recv_budget = XDTLS_RX_SLOTS * 2;
    cfg.on_datagram = bounded_input; cfg.userdata = &input;
    xUdp *receiver = xudp_bind("127.0.0.1", 0, &cfg, error);
    xUdp *sender = xudp_bind("127.0.0.1", 0, NULL, error);
    assert(receiver && sender);
    a.write_wait = receiver;
    b.udp = sender; assert(!xudp_sockname(receiver, &b.destination));
    a.block = 3;
    assert(xdtls_write(a.dtls, "pending", 7) == XDTLS_AGAIN);
    unsigned char out[2048];
    for (unsigned char i = 0; i < XDTLS_RX_SLOTS + 8; ++i)
        assert(xdtls_write(b.dtls, &i, 1) == 1);
    for (int i = 0; i < 100 && input.received < XDTLS_RX_SLOTS; ++i) xpoll_poll(5);
    assert(input.received == XDTLS_RX_SLOTS && !input.rejected);
    assert(!xdtls_input_space(a.dtls));
    for (int i = 0; i < 2; ++i) {
        assert(xdtls_write(a.dtls, "pending", 7) == XDTLS_AGAIN);
        assert(xdtls_read(a.dtls, out, sizeof(out)) == XDTLS_AGAIN);
        assert(xpoll_poll(100) > 0); /* writable wakes even while RX is paused */
        assert(xpoll_poll(0) == 0); /* one shot, no writable busy loop */
        assert(input.received == XDTLS_RX_SLOTS && !input.rejected);
    }
    assert(xdtls_write_pending(a.dtls));
    assert(xdtls_write(a.dtls, "pending", 7) == 7);
    assert(!xdtls_write_pending(a.dtls));
    /* Drain before resuming, including when only part of the queue fits. */
    for (unsigned char i = 0; i < 4; ++i)
        assert(xdtls_read(a.dtls, out, sizeof(out)) == 1 && out[0] == i);
    assert(xdtls_input_space(a.dtls) == 4);
    assert(!xudp_resume_read(receiver));
    for (int i = 0; i < 100 && input.received < XDTLS_RX_SLOTS + 4; ++i) xpoll_poll(5);
    assert(input.received == XDTLS_RX_SLOTS + 4 && !input.rejected);
    for (unsigned char i = 4; i < XDTLS_RX_SLOTS + 4; ++i)
        assert(xdtls_read(a.dtls, out, sizeof(out)) == 1 && out[0] == i);
    assert(!xudp_resume_read(receiver));
    assert(!xudp_resume_read(receiver)); /* idempotent */
    for (int i = 0; i < 100 && input.received < XDTLS_RX_SLOTS + 8; ++i) xpoll_poll(5);
    assert(input.received == XDTLS_RX_SLOTS + 8 && !input.rejected);
    for (unsigned char i = XDTLS_RX_SLOTS + 4; i < XDTLS_RX_SLOTS + 8; ++i)
        assert(xdtls_read(a.dtls, out, sizeof(out)) == 1 && out[0] == i);
    assert(xdtls_read(a.dtls, out, sizeof(out)) == XDTLS_AGAIN);
    assert(xdtls_read(b.dtls, out, sizeof(out)) == 7 && !memcmp(out, "pending", 7));
    assert(xdtls_read(b.dtls, out, sizeof(out)) == XDTLS_AGAIN);
    /* Reset while full/paused must allow the replacement session to receive. */
    for (unsigned char i = 0; i < XDTLS_RX_SLOTS; ++i)
        assert(xdtls_write(b.dtls, &i, 1) == 1);
    for (int i = 0; i < 100 && xdtls_input_space(a.dtls); ++i) xpoll_poll(5);
    assert(!xdtls_input_space(a.dtls) && !input.rejected);
    destroy(&a, &b); pair(&a, &b, 0, 0); assert(handshake(&a, &b));
    input.dtls = a.dtls;
    b.udp = sender; assert(!xudp_sockname(receiver, &b.destination));
    assert(!xudp_resume_read(receiver));
    unsigned before = input.received;
    assert(xdtls_write(b.dtls, "reset", 5) == 5);
    for (int i = 0; i < 100 && input.received == before; ++i) xpoll_poll(5);
    assert(input.received == before + 1 && !input.rejected);
    assert(xdtls_read(a.dtls, out, sizeof(out)) == 5 && !memcmp(out, "reset", 5));
    xudp_destroy(sender);
    xUdpStats diag; xudp_get_stats(receiver,&diag);
    assert(diag.read_events && diag.read_event_age_ms>=0);
    uint64_t pauses=diag.read_pauses, resumes=diag.read_resumes, writes=diag.write_events;
    xudp_pause_read(receiver); xudp_pause_read(receiver);
    xudp_get_stats(receiver,&diag);
    assert(diag.read_paused && diag.read_pauses==pauses+1);
    assert(xpoll_fd_count() == 1); /* retain error watch even with no readable fd */
    assert(!xudp_wait_writable(receiver, true));
    assert(!xudp_wait_writable(receiver, true)); /* idempotent arm */
    xudp_get_stats(receiver,&diag); assert(diag.write_waiting);
    assert(xpoll_poll(100) > 0);
    xudp_get_stats(receiver,&diag);
    assert(!diag.write_waiting && diag.write_events==writes+1 && diag.write_event_age_ms>=0);
    assert(xpoll_poll(0) == 0);
    assert(!xudp_wait_writable(receiver, true));
    assert(!xudp_wait_writable(receiver, false)); /* cancel before readiness */
    assert(xpoll_poll(0) == 0);
    assert(!xudp_resume_read(receiver)); /* restoring RX must preserve write watch */
    xudp_get_stats(receiver,&diag);
    assert(!diag.read_paused && diag.read_resumes==resumes+1);
    assert(!xudp_wait_writable(receiver, true));
    xudp_pause_read(receiver);
    assert(!xudp_resume_read(receiver));
    assert(xpoll_poll(100) > 0);
    assert(xpoll_poll(0) == 0);
    assert(!xudp_wait_writable(receiver, true)); /* close while armed */
    xudp_destroy(receiver);
    assert(!xudp_live_count() && !xudp_socket_count());
    xudp_get_stats(NULL,&diag);
    assert(!diag.read_events && diag.read_event_age_ms==-1 && diag.write_event_age_ms==-1);
    xpoll_uninit(); socket_cleanup(); destroy(&a, &b);
    puts("PASS full-duplex backpressure, one-shot writable wakeups, cancellation and read pause/resume without loss/duplicates");
}
static void packet_tests(void) {
    XtConfig c = {0}; XtRoute route;
    assert(xt_parse_ip("10.77.0.2", &c.address));
    assert(xt_parse_ip("10.77.0.1", &c.peer_address));
    assert(xt_parse_route("10.77.0.1/32", &c.routes[0])); c.route_count = 1;
    assert(xt_parse_route("10.77.0.2/32", &c.local_networks[0])); c.local_count = 1;
    assert(!xt_parse_route("10.0.0.1/24", &route));
    assert(!xt_parse_route("10.0.0.0/33", &route));
    unsigned char ip[20] = {0x45,0,0,20,0,0,0,0,64,17,0,0,10,77,0,1,10,77,0,2};
    unsigned sum = 0;
    for (unsigned i=0;i<20;i+=2) sum += (unsigned)ip[i]*256+ip[i+1];
    while(sum>>16)sum=(sum&65535)+(sum>>16);
    sum=~sum;ip[10]=sum>>8;ip[11]=sum;
    assert(xt_packet_valid(&c,ip,sizeof(ip),1));
    assert(!xt_packet_valid(&c,ip,sizeof(ip),0));
    ip[19]^=1; assert(!xt_packet_valid(&c,ip,sizeof(ip),1)); ip[19]^=1;
    c.routes[0].network++; assert(!xt_packet_valid(&c,ip,sizeof(ip),1));
    assert(!xt_packet_valid(&c,ip,19,1));
    --c.routes[0].network;
    unsigned char large[1351] = {0}; memcpy(large, ip, 20);
    large[2] = 1350 >> 8; large[3] = 1350 & 255; large[10] = large[11] = 0;
    sum = 0; for (unsigned i=0;i<20;i+=2) sum += (unsigned)large[i]*256+large[i+1];
    while (sum>>16) sum=(sum&65535)+(sum>>16);
    sum=~sum; large[10]=sum>>8; large[11]=sum;
    assert(!xt_packet_valid(&c, large, 1350, 1));
    c.mtu = 1350;
    assert(xt_packet_valid(&c, large, 1350, 1));
    assert(!xt_packet_valid(&c, large, 1351, 1));
    /* Routed LAN packets must pass both peers, in both directions, while
       sources/destinations outside the explicitly allowed LANs stay blocked. */
    XtConfig client = {0}, server = {0}; server.server = 1;
    assert(xt_parse_route("192.168.1.0/24", &client.local_networks[0])); client.local_count = 1;
    assert(xt_parse_route("10.10.0.0/16", &client.routes[0])); client.route_count = 1;
    server.local_networks[0] = client.routes[0]; server.local_count = 1;
    server.routes[0] = client.local_networks[0]; server.route_count = 1;
    for (unsigned reverse = 0; reverse < 2; ++reverse) {
        unsigned char lan[20] = {0x45,0,0,20,0,0,0,0,64,17};
        const unsigned char local[4] = {192,168,1,10}, remote[4] = {10,10,0,20};
        memcpy(lan+12, reverse ? remote : local, 4);
        memcpy(lan+16, reverse ? local : remote, 4);
        sum = 0; for (unsigned i=0;i<20;i+=2) sum += (unsigned)lan[i]*256+lan[i+1];
        while (sum>>16) sum=(sum&65535)+(sum>>16);
        sum=~sum; lan[10]=sum>>8; lan[11]=sum;
        assert(xt_packet_valid(&client,lan,sizeof(lan),reverse));
        assert(xt_packet_valid(&server,lan,sizeof(lan),!reverse));
        client.local_count = 0;
        assert(!xt_packet_valid(&client,lan,sizeof(lan),reverse));
        client.local_count = 1;
        server.route_count = 0;
        assert(!xt_packet_valid(&server,lan,sizeof(lan),!reverse));
        server.route_count = 1;
    }
    puts("PASS IPv4 length/checksum validation and address authorization");
}
static void replay_window_tests(void) {
    const unsigned distances[]={63,64,127,MBEDTLS_SSL_DTLS_REPLAY_WINDOW-1,
                                MBEDTLS_SSL_DTLS_REPLAY_WINDOW,MBEDTLS_SSL_DTLS_REPLAY_WINDOW+65};
    for (unsigned test=0;test<sizeof(distances)/sizeof(*distances);++test) {
        End a,b; pair(&a,&b,0,0); assert(handshake(&a,&b));
        unsigned char held[XDTLS_MAX_RECORD],out[2048];
        a.hold=1; assert(xdtls_write(a.dtls,"old",3)==3);
        size_t held_len=a.saved_len; memcpy(held,a.saved,held_len); a.hold=0;
        for (unsigned i=0;i<distances[test];++i) {
            assert(xdtls_write(a.dtls,"new",3)==3);
            assert(xdtls_read(b.dtls,out,sizeof(out))==3);
        }
        assert(!xdtls_feed(b.dtls,held,held_len));
        int expected=distances[test]<MBEDTLS_SSL_DTLS_REPLAY_WINDOW ? 3 : XDTLS_AGAIN;
        assert(xdtls_read(b.dtls,out,sizeof(out))==expected);
        assert(!xdtls_feed(b.dtls,held,held_len));
        assert(xdtls_read(b.dtls,out,sizeof(out))==XDTLS_AGAIN); /* duplicate stays rejected */
        destroy(&a,&b);
    }
    /* Compare boundary and random shifts with an independent receipt-history model. */
    mbedtls_ssl_context ssl; mbedtls_ssl_config conf;
    mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&conf);
    conf.MBEDTLS_PRIVATE(anti_replay)=MBEDTLS_SSL_ANTI_REPLAY_ENABLED;
    ssl.MBEDTLS_PRIVATE(conf)=&conf;
    unsigned char ctr[8]={0}; ssl.MBEDTLS_PRIVATE(in_ctr)=ctr;
    unsigned char *seen=calloc(300000,1); assert(seen);
    unsigned top=0,rng=7;
    for (unsigned i=0;i<20000;++i) {
        rng=rng*1664525u+1013904223u;
        unsigned seq;
        if (i%101==0) seq=top+MBEDTLS_SSL_DTLS_REPLAY_WINDOW+1;
        else if (i%3==0) seq=top+1+rng%130;
        else seq=top>MBEDTLS_SSL_DTLS_REPLAY_WINDOW+1 ? top-rng%(MBEDTLS_SSL_DTLS_REPLAY_WINDOW+2) : rng%(top+1);
        /* Keep the oracle bounded while also exercising window reset. */
        if (seq>=300000) {
            mbedtls_ssl_dtls_replay_reset(&ssl); memset(seen,0,300000); top=seq=0;
        }
        for (unsigned j=0;j<6;++j) ctr[7-j]=(unsigned char)((uint64_t)seq>>(8*j));
        int accept=(seq>top || top-seq<MBEDTLS_SSL_DTLS_REPLAY_WINDOW) && !seen[seq];
        assert((mbedtls_ssl_dtls_replay_check(&ssl)==0)==accept);
        if (accept) {
            mbedtls_ssl_dtls_replay_update(&ssl); seen[seq]=1;
            if (seq>top) top=seq;
            assert(mbedtls_ssl_dtls_replay_check(&ssl)==-1);
        }
    }
    free(seen);
    /* Stack-owned pointers must not be passed to ssl_free. No setup allocated buffers. */
    ssl.MBEDTLS_PRIVATE(in_ctr)=NULL; ssl.MBEDTLS_PRIVATE(conf)=NULL;
    mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf);
    printf("PASS DTLS replay window=%u, encrypted reorder boundaries, duplicate rejection and history model\n",
           MBEDTLS_SSL_DTLS_REPLAY_WINDOW);
}
int main(void) {
    replay_window_tests();
    channel_tests();
    udp_test();
    duplex_backpressure_test();
    packet_tests();
    puts("ALL TESTS PASSED");
    return 0;
}
