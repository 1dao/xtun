#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xdtls.h"
#include "xudp.h"
#include "xpoll.h"
#include "xtun.h"

typedef struct End {
    xDtls *dtls;
    struct End *peer;
    int drop, block, hold;
    unsigned char saved[XDTLS_MAX_RECORD];
    size_t saved_len;
    unsigned sent;
} End;
static int transport(void *p, const unsigned char *data, size_t n) {
    End *e = p;
    if (e->block) { --e->block; return XDTLS_AGAIN; }
    ++e->sent;
    memcpy(e->saved, data, n); e->saved_len = n;
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
    printf("PASS handshake survives initial packet loss; suite=%s\n", xdtls_suite(a.dtls));
    a.block = 1;
    assert(xdtls_write(a.dtls, message, sizeof(message)) == XDTLS_AGAIN);
    assert(xdtls_write(a.dtls, message, sizeof(message)) == sizeof(message));
    assert(xdtls_read(b.dtls, buf, sizeof(buf)) == sizeof(message));
    assert(!memcmp(message, buf, sizeof(message)));
    puts("PASS binary datagrams and send backpressure");
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
    puts("PASS IPv4 length/checksum validation and address authorization");
}
int main(void) {
    channel_tests();
    udp_test();
    packet_tests();
    puts("ALL TESTS PASSED");
    return 0;
}
