/* Include the owner to test its real queue/timer state without test-only APIs. */
#define xt_device_write test_device_write
#include "../src/tunnel.c"
#include <assert.h>
#ifdef _WIN32
#include <io.h>
#define dup _dup
#define dup2 _dup2
#define close _close
#else
#include <unistd.h>
#endif

static unsigned char delivered_bytes[ARQ_WINDOW * 2];
static unsigned delivered_count;
static int delivery_blocked;
int test_device_write(XtDevice *dev, const void *bytes, size_t n) {
    (void)dev;
    if (delivery_blocked) return 0;
    assert(delivered_count < sizeof(delivered_bytes));
    delivered_bytes[delivered_count++] = *(const unsigned char *)bytes;
    return (int)n;
}

static void ordered_delivery_test(void) {
    XtConfig cfg = {0};
    Tunnel *t = calloc(1, sizeof(*t)); assert(t);
    t->cfg = &cfg; t->arq = calloc(1, sizeof(Arq)); assert(t->arq);
    t->dev = (XtDevice *)t; t->now = 10000;
    delivered_count = 0;
    assert(arq_store_packet(t, 2, "B", 1) == 1);
    assert(!delivered_count && t->arq->buffered == 1 && t->arq->missing == 1);
    assert(arq_store_packet(t, 2, "B", 1) == 0);
    t->now += ARQ_ORDER_WAIT-1; arq_drain(t,0);
    assert(!delivered_count && t->arq->buffered == 1 && t->arq->missing == 1);
    assert(arq_store_packet(t, 1, "A", 1) == 1);
    assert(delivered_count == 2 && !memcmp(delivered_bytes,"AB",2));
    assert(!t->arq->buffered && !t->arq->missing);
    assert(arq_store_packet(t, 4, "D", 1) == 1);
    t->now += ARQ_ORDER_WAIT-1; arq_drain(t,0); assert(delivered_count == 2);
    ++t->now; arq_drain(t,0);
    assert(delivered_count == 3 && delivered_bytes[2] == 'D' && t->arq_order_skips == 1);
    assert(t->arq->missing==1 && !t->arq->rx[3].expired);
    assert(arq_store_packet(t, 3, "C", 1) == 1);
    assert(delivered_count==4 && delivered_bytes[3]=='C' && !t->arq->missing);
    assert(arq_store_packet(t, 3, "C", 1) == 0);
    delivery_blocked = 1;
    assert(arq_store_packet(t, 5, "E", 1) == 1 && delivered_count == 4);
    delivery_blocked = 0; arq_drain(t,0);
    assert(delivered_count == 5 && delivered_bytes[4] == 'E');
    /* Filling the ring must drain before overwriting queued payloads. */
    for (unsigned i=7; i<=ARQ_WINDOW+6; ++i) {
        unsigned char byte=(unsigned char)i;
        assert(arq_store_packet(t,(uint16_t)i,&byte,1)==1);
    }
    assert(t->arq->delivered == ARQ_WINDOW+6 && !t->arq->buffered && t->arq_order_skips == 2);
    memset(t->arq,0,sizeof(*t->arq)); delivered_count=0;
    t->arq->high=t->arq->delivered=65534;
    assert(arq_store_packet(t,0,"B",1)==1 && !delivered_count);
    assert(arq_store_packet(t,65535,"A",1)==1);
    assert(delivered_count==2 && !memcmp(delivered_bytes,"AB",2) && t->arq->delivered==65536);
    delivery_blocked=1;
    assert(arq_store_packet(t,1,"C",1)==1);
    t->now+=ARQ_CACHE_TTL; arq_drain(t,0);
    assert(!t->arq->buffered && t->drop_tun_write==1 && delivered_count==2);
    delivery_blocked=0;
    free(t->arq); free(t);
    puts("PASS ordered delivery, deduplication, timeout, local retry and ring eviction");
}

static void separate_order_deadline_test(void) {
    XtConfig cfg={0}; Tunnel *t=calloc(1,sizeof(*t)); assert(t);
    t->cfg=&cfg; t->arq=calloc(1,sizeof(Arq)); assert(t->arq);
    t->dev=(XtDevice *)t; t->now=10000; delivered_count=0;
    assert(arq_store_packet(t,2,"B",1)==1);
    t->now+=ARQ_ORDER_WAIT-1; arq_drain(t,0); assert(!delivered_count);
    ++t->now; arq_drain(t,0);
    assert(delivered_count==1 && delivered_bytes[0]=='B');
    assert(t->arq->missing==1 && !t->arq->rx[1].expired && !t->arq_expired);
    assert(t->arq->received_through==0);
    unsigned char feedback[ARQ_NACK_BYTES]; uint16_t ids[ARQ_WINDOW];
    unsigned n=arq_feedback(t,feedback);
    assert(arq_nack_decode(ARQ_NACK_PACKED,feedback,n,ids)==1 && ids[0]==1);
    t->now+=1000; delivery_blocked=1;
    assert(arq_store_packet(t,1,"A",1)==0 && t->arq->missing==1 && !t->arq->rx[1].received);
    delivery_blocked=0;
    assert(arq_store_packet(t,1,"A",1)==1);
    assert(delivered_count==2 && !memcmp(delivered_bytes,"BA",2));
    assert(t->arq->received_through==2 && !t->arq->missing);
    assert(arq_store_packet(t,1,"A",1)==0 && delivered_count==2);
    /* Recovery remains possible just before the independent cache deadline. */
    assert(arq_store_packet(t,4,"D",1)==1);
    t->now+=ARQ_CACHE_TTL-1; arq_drain(t,0);
    assert(arq_store_packet(t,3,"C",1)==1 && t->arq->received_through==4);
    assert(delivered_count==4 && !memcmp(delivered_bytes,"BADC",4));
    assert(arq_store_packet(t,6,"F",1)==1);
    t->now+=ARQ_ORDER_WAIT; arq_drain(t,0);
    t->now+=ARQ_CACHE_TTL-ARQ_ORDER_WAIT;
    assert(arq_store_packet(t,5,"E",1)==0 && delivered_count==5);
    arq_timer_update(t); assert(!t->arq->missing && t->arq_expired_ttl==1);
    assert(t->arq->received_through==4);
    /* Late delivery and cumulative receipt also work across wire rollover. */
    memset(t->arq,0,sizeof(*t->arq)); delivered_count=0;
    t->arq->high=t->arq->delivered=t->arq->received_through=65534;
    assert(arq_store_packet(t,0,"B",1)==1);
    t->now+=ARQ_ORDER_WAIT; arq_drain(t,0);
    assert(arq_store_packet(t,65535,"A",1)==1);
    assert(t->arq->received_through==65536 && delivered_count==2 && !memcmp(delivered_bytes,"BA",2));
    assert(arq_store_packet(t,65535,"A",1)==0);
    free(t->arq); free(t);
    puts("PASS independent 200ms ordering and 5s repair, late delivery, deduplication, local backpressure and rollover");
}

typedef struct {
    Tunnel *t, *peer;
    int block, drop;
    unsigned sent;
    unsigned char cipher[XDTLS_MAX_RECORD]; size_t len;
} Link;
typedef struct { XtConfig ca, cb; Tunnel *a, *b; Link ab, ba; } Pair;
static int output(void *p, const unsigned char *bytes, size_t n) {
    Link *l = p;
    if (l->block) { --l->block; return XDTLS_AGAIN; }
    ++l->sent; memcpy(l->cipher, bytes, n); l->len=n;
    if (l->drop) { --l->drop; return (int)n; }
    assert(!xdtls_feed(l->peer->dtls, bytes, n)); return (int)n;
}
static void init(Pair *p) {
    memset(p, 0, sizeof(*p));
    p->a=calloc(1, sizeof(Tunnel)); p->b=calloc(1, sizeof(Tunnel)); assert(p->a && p->b);
    p->a->cfg=&p->ca; p->b->cfg=&p->cb;
    p->ca.probe=p->cb.probe=1; p->ca.mtu=p->cb.mtu=XT_MTU;
    p->ab=(Link){.t=p->a,.peer=p->b}; p->ba=(Link){.t=p->b,.peer=p->a};
    unsigned char key[32]; memset(key, 0x51, sizeof(key)); char error[256];
    xDtlsConfig c={0}; c.psk=key; c.identity="arq-test"; c.send=output; c.userdata=&p->ab;
    p->a->dtls=xdtls_create(&c,error); assert(p->a->dtls);
    c.server=1; c.transport_id="test"; c.transport_id_len=4; c.userdata=&p->ba;
    p->b->dtls=xdtls_create(&c,error); assert(p->b->dtls);
    for (uint64_t now=0; now<10000; now+=10) {
        assert(xdtls_step(p->a->dtls,now)>=0 && xdtls_step(p->b->dtls,now)>=0);
        if (xdtls_ready(p->a->dtls) && xdtls_ready(p->b->dtls)) break;
    }
    assert(xdtls_ready(p->a->dtls) && xdtls_ready(p->b->dtls));
    p->a->now=p->b->now=10000; p->a->active=p->b->active=1;
    p->a->arq=calloc(1,sizeof(Arq)); p->b->arq=calloc(1,sizeof(Arq));
    assert(p->a->arq && p->b->arq);
}
static void finish(Pair *p) {
    xdtls_destroy(p->a->dtls); xdtls_destroy(p->b->dtls);
    free(p->a->arq); free(p->b->arq); free(p->a); free(p->b);
}
static void encrypted_order_test(void) {
    Pair p; init(&p);
    p.cb.probe=0; p.cb.full_tunnel=1;
    p.cb.local_count=1; p.cb.local_networks[0]=(XtRoute){0};
    p.b->dev=(XtDevice *)p.b;
    unsigned char packet[20]={0x45,0,0,20,0,0,0,0,64,6,0,0,192,0,2,1,10,0,0,2};
    unsigned sum=0;
    for(unsigned i=0;i<20;i+=2) sum+=((unsigned)packet[i]<<8)|packet[i+1];
    while(sum>>16) sum=(sum&65535)+(sum>>16);
    packet[10]=(unsigned char)(~sum>>8); packet[11]=(unsigned char)~sum;
    delivered_count=0;
    p.ab.drop=1;
    assert(enqueue(p.a,DATA,packet,sizeof(packet)) && flush(p.a,XT_QUEUE));
    assert(enqueue(p.a,DATA,packet,sizeof(packet)) && flush(p.a,XT_QUEUE));
    assert(receive_messages(p.b));
    assert(!delivered_count && p.b->arq->buffered==1 && p.b->arq->missing==1);
    p.b->now+=5; arq_tick(p.b); assert(flush(p.b,XT_QUEUE));
    assert(receive_messages(p.a)); assert(flush(p.a,XT_QUEUE));
    assert(receive_messages(p.b));
    assert(delivered_count==2 && p.b->rx_packets==2 && p.b->rx_bytes==40);
    assert(!p.b->arq->buffered && !p.b->arq->missing && p.b->arq->delivered==2);
    p.ab.drop=1;
    assert(enqueue(p.a,DATA,packet,sizeof(packet)) && flush(p.a,XT_QUEUE));
    assert(enqueue(p.a,DATA,packet,sizeof(packet)) && flush(p.a,XT_QUEUE));
    assert(receive_messages(p.b) && delivered_count==2);
    p.b->now+=ARQ_ORDER_WAIT; p.a->now=p.b->now; arq_tick(p.b);
    assert(delivered_count==3 && p.b->arq->missing==1 && p.b->arq->received_through==2);
    assert(flush(p.b,XT_QUEUE) && receive_messages(p.a) && flush(p.a,XT_QUEUE));
    assert(receive_messages(p.b));
    assert(delivered_count==4 && p.b->arq->received_through==4 && !p.b->arq->missing);
    assert(!p.b->arq_expired && !p.b->arq->buffered);
    finish(&p);
    puts("PASS real DTLS ordered recovery and late IP delivery after ordering timeout");
}
static void send_data(Tunnel *t) {
    assert(enqueue(t,DATA,"packet",6)); assert(flush(t,XT_QUEUE));
}
static int take_data(Tunnel *t, uint16_t expected) {
    unsigned char out[2048]; int n=xdtls_read(t->dtls,out,sizeof(out));
    assert(n==XT_HEADER+2+6 && out[1]==ARQ_DATA && be16(out+8)==expected);
    assert(!memcmp(out+10,"packet",6));
    int rc=arq_receive(t,expected,0);
    if (rc==1) assert(arq_receive(t,expected,1)==1);
    return rc;
}
static void control(Tunnel *t) { assert(receive_messages(t)); }
static void feedback(Tunnel *t) {
    arq_tick(t);
    if (t->arq->timer && t->now<t->arq->nack_due) { t->now=t->arq->nack_due; arq_tick(t); }
    assert(flush(t,XT_QUEUE));
}
static void timer_test(void) {
    Pair p; init(&p); Tunnel *b=p.b;
    assert(arq_receive(b,2,1)==1); assert(b->arq->missing==1);
    const unsigned times[]={0,20,70,170,370,570};
    arq_tick(b); assert(b->arq->nack_due==10000 && b->count==1);
    for (unsigned i=0;i<sizeof(times)/sizeof(times[0]);++i) {
        if (i) { b->now=10000+times[i]-1; arq_tick(b); assert(!b->count); }
        b->now=10000+times[i]; feedback(b); control(p.a);
        assert(b->arq_nacks==i+1 && b->arq->timer);
    }
    /* A new gap gets its own grace period while old gaps keep their backoff. */
    uint64_t due=b->arq->nack_due;
    assert(arq_receive(b,4,1)==1); arq_tick(b); assert(b->arq->nack_due==b->now);
    assert(b->arq->rx[1].feedback_due==due);
    uint64_t requests=p.a->arq_requests;
    feedback(b); control(p.a);
    assert(p.a->arq_requests==requests+1 && b->arq->rx[3].requested);
    assert(b->arq->rx[1].feedback_due==due && b->arq->rx[3].feedback_due==b->now+20);
    assert(arq_receive(b,1,1)==1 && arq_receive(b,3,1)==1);
    assert(!b->arq->missing && !b->arq->timer);
    b->now+=100; arq_tick(b); assert(!b->count);
    /* Resolve a gap while feedback is queued: cancel before encrypting it. */
    assert(arq_receive(b,6,1)==1); b->now+=5; arq_tick(b); assert(b->count==1);
    unsigned before=p.ba.sent;
    assert(arq_receive(b,5,1)==1); assert(flush(b,XT_QUEUE));
    assert(p.ba.sent==before && !b->count && !b->arq->nack_queued);
    finish(&p); puts("PASS immediate first feedback, per-gap 20/50/100/200ms backoff, new-gap independence and cancellation");
}
static void independent_batch_test(void) {
    Pair p; init(&p); Tunnel *b=p.b;
    assert(arq_receive(b,2,1)==1 && arq_receive(b,4,1)==1);
    b->now+=5; feedback(b); control(p.a);
    assert(b->arq->rx[1].feedback_due==10025 && b->arq->rx[3].feedback_due==10025);
    b->now=10025; feedback(b); control(p.a);
    assert(b->arq->rx[1].feedback_due==10075 && b->arq->rx[3].feedback_due==10075);
    b->now=10030; assert(arq_receive(b,1,1)==1);
    assert(b->arq->rx[3].feedback_due==10075 && b->arq->rx[3].delay==100);
    /* A fresh gap gets its first request without restarting the older gap. */
    assert(arq_receive(b,6,1)==1); b->now=10035; feedback(b); control(p.a);
    assert(b->arq->rx[5].feedback_due==10055 && b->arq->rx[3].feedback_due==10075);
    b->now=10055; feedback(b); control(p.a);
    assert(b->arq->rx[5].feedback_due==10105 && b->arq->rx[3].feedback_due==10075);
    b->now=10075; feedback(b); control(p.a);
    assert(b->arq->rx[3].feedback_due==10175 && b->arq->rx[5].feedback_due==10105);
    finish(&p); puts("PASS batched gaps keep independent cooldowns after earlier gaps are repaired");
}
static void long_recovery_test(void) {
    Pair p; init(&p);
    p.ab.drop=1; send_data(p.a); send_data(p.a); assert(take_data(p.b,2)==1);
    for (unsigned i=1;i<=21;++i) {
        p.a->now=p.b->now=10000+i*200;
        feedback(p.b); control(p.a);
        assert(p.a->count==1);
        p.ab.drop=i<21; assert(flush(p.a,XT_QUEUE));
    }
    assert(take_data(p.b,1)==1 && !p.b->arq->missing);
    assert(p.a->arq_retransmits==21 && !p.a->arq_retry_skip);
    p.a->now=10000+ARQ_CACHE_TTL;
    arq_request(p.a,1); assert(!p.a->count && p.a->arq_cache_ttl==1);
    finish(&p); puts("PASS twenty lost repairs still recover after 4.2s, expiry remains bounded");
}
static void recovery_test(void) {
    Pair p; init(&p);
    send_data(p.a); assert(take_data(p.b,1)==1);
    p.ab.drop=1; send_data(p.a); send_data(p.a); assert(take_data(p.b,3)==1);
    p.ba.drop=1; feedback(p.b); /* first NACK is lost */
    p.b->now+=20; feedback(p.b); control(p.a); assert(p.a->count==1);
    arq_request(p.a,2); assert(p.a->count==1); /* duplicate request cannot queue twice */
    p.ab.block=1; assert(flush(p.a,1)); assert(xdtls_write_pending(p.a->dtls));
    size_t pending=p.a->queue[p.a->head].len;
    assert(receive_messages(p.a)); assert(p.a->queue[p.a->head].len==pending);
    p.ab.drop=1; assert(flush(p.a,1)); /* first retransmission is lost */
    assert(p.a->arq_retransmits==1);
    p.b->now+=40; feedback(p.b); control(p.a); assert(!p.a->count); /* cooldown */
    p.a->now+=140; p.b->now=10140; feedback(p.b); control(p.a);
    p.ab.drop=1; assert(p.a->count==1 && flush(p.a,1)); /* second repair is also lost */
    p.a->now+=160; p.b->now=p.a->now; feedback(p.b); control(p.a);
    assert(p.a->count==1 && flush(p.a,1)); assert(take_data(p.b,2)==1);
    assert(!p.b->arq->missing && !p.b->arq->timer && p.a->arq_retransmits==3);
    p.a->now+=160;
    p.a->arq->tx[2].retries=ARQ_REPAIR_LIMIT;
    arq_request(p.a,2); assert(!p.a->count); /* actual retry limit */
    assert(p.a->arq_retry_skip==1);
    /* Fresh DTLS records can carry a duplicate app sequence, delivered once. */
    ArqTx *cached=&p.a->arq->tx[2];
    assert(enqueue(p.a,ARQ_DATA,cached->bytes,cached->len));
    p.a->queue[p.a->head].retry=1; p.a->queue[p.a->head].expires=11000;
    assert(flush(p.a,1)); assert(take_data(p.b,2)==0);
    assert(!xdtls_feed(p.b->dtls,p.ab.cipher,p.ab.len));
    unsigned char out[2048]; assert(xdtls_read(p.b->dtls,out,sizeof(out))==XDTLS_AGAIN);
    finish(&p); puts("PASS lost NACK/lost repair recovery, write backpressure, cooldown, retry limit and deduplication");
}
static void priority_test(void) {
    Pair p; init(&p);
    p.ab.drop=2; send_data(p.a); send_data(p.a);
    p.a->head=XT_QUEUE-1; /* exercise rotation across the ring boundary */
    assert(enqueue(p.a,DATA,"packet",6)); assert(enqueue(p.a,DATA,"packet",6));
    arq_request(p.a,1); arq_request(p.a,2);
    const unsigned order[]={1,2,3,4};
    for (unsigned i=0;i<4;++i) {
        assert(flush(p.a,1)); assert(take_data(p.b,(uint16_t)order[i])==1);
    }
    assert(p.a->arq->sent==4 && p.a->arq_retransmits==2 && !p.a->count);
    finish(&p);
    init(&p); p.ab.drop=1; send_data(p.a);
    assert(enqueue(p.a,DATA,"packet",6)); assert(enqueue(p.a,DATA,"packet",6));
    p.ab.block=1; assert(flush(p.a,1)); assert(xdtls_write_pending(p.a->dtls));
    unsigned char saved[sizeof(p.a->queue[0])];
    memcpy(saved,&p.a->queue[p.a->head],sizeof(saved));
    arq_request(p.a,1); arq_prioritize_repair(p.a);
    assert(!memcmp(saved,&p.a->queue[p.a->head],sizeof(saved)));
    assert(flush(p.a,1)); assert(take_data(p.b,2)==1);
    assert(flush(p.a,1)); assert(take_data(p.b,1)==1);
    assert(flush(p.a,1)); assert(take_data(p.b,3)==1);
    assert(p.a->arq->sent==3 && !p.a->count);
    finish(&p); puts("PASS repair priority, ring wrap, original/repair FIFO and immutable pending DATA");
}
static void reorder_test(void) {
    Pair p; init(&p); Tunnel *b=p.b;
    /* Immediate feedback can still be cancelled if the gap fills before send. */
    for (unsigned seq=1; seq<1000; seq+=2) {
        assert(arq_receive(b,(uint16_t)(seq+1),1)==1);
        arq_tick(b); assert(b->count==1 && b->arq->nack_due==b->now);
        ++b->now; assert(arq_receive(b,(uint16_t)seq,1)==1);
        arq_tick(b); assert(flush(b,XT_QUEUE));
        assert(!b->count && !b->arq->timer);
        b->now+=9;
    }
    assert(!b->arq_nacks && !b->arq->missing);
    finish(&p);
    init(&p); b=p.b;
    assert(arq_receive(b,2,1)==1); arq_tick(b); assert(b->count==1);
    /* Refresh queued feedback to combine all currently missing fresh IDs. */
    assert(arq_receive(b,4,1)==1);
    assert(flush(b,XT_QUEUE)); control(p.a);
    assert(p.a->arq_requests==2 && b->arq->rx[1].requested && b->arq->rx[3].requested);
    uint64_t old_due=b->arq->rx[1].feedback_due;
    ++b->now; arq_tick(b);
    assert(!b->count && b->arq->rx[1].feedback_due==old_due && b->arq->rx[3].feedback_due==old_due);
    finish(&p); puts("PASS immediate first NACK, cancellation, fresh-gap batching and retry suppression");
}
static void watermark_test(void) {
    Pair p; init(&p); p.ab.drop=1; send_data(p.a);
    p.a->now+=199; arq_tick(p.a); assert(!p.a->count);
    ++p.a->now; feedback(p.a); control(p.b); assert(p.b->arq->missing==1);
    feedback(p.b); control(p.a); assert(p.a->count==1 && flush(p.a,1));
    assert(take_data(p.b,1)==1); /* no later DATA was needed */
    p.a->now+=200; feedback(p.a); control(p.b); assert(!p.b->arq->missing);
    p.a->now=p.a->arq->last_data+2*ARQ_CACHE_TTL; arq_tick(p.a); assert(!p.a->count); /* stop after cache lifetime */
    finish(&p); puts("PASS 200ms sender-only watermark, tail recovery and idle suppression");
}
static void wrap_test(void) {
    Pair p; init(&p);
    for (unsigned i=1;i<=70000;++i) {
        if (i==65536) p.ab.drop=1;
        send_data(p.a);
        if (i==65536) continue;
        assert(take_data(p.b,(uint16_t)i)==1);
        if (i==65537) {
            assert(p.b->arq->missing==1); feedback(p.b); control(p.a);
            assert(flush(p.a,1)); assert(take_data(p.b,0)==1);
            assert(p.b->arq->rx[0].seq==65536 && !p.b->arq->missing);
        }
    }
    assert(p.a->arq->sent==70000 && p.b->arq->high==70000);
    assert(arq_receive(p.b,(uint16_t)70000,1)==0);
    assert(arq_receive(p.b,(uint16_t)(70000+32768),1)==-1);
    assert(arq_receive(p.b,(uint16_t)(70000+ARQ_WINDOW),1)==-1);
    arq_request(p.a,(uint16_t)(70000-ARQ_WINDOW)); assert(!p.a->count && p.a->arq_cache_miss);
    finish(&p); puts("PASS 70,000 DATA messages, 16-bit rollover including lost zero, bounded cache and ambiguous jump rejection");
}
static void bounds_test(void) {
    Pair p; init(&p); send_data(p.a); assert(take_data(p.b,1)==1);
    arq_request(p.a,1); assert(p.a->count==1 && !p.a->arq_limited);
    p.a->now+=ARQ_CACHE_TTL; assert(flush(p.a,1));
    assert(!p.a->count && !p.a->arq_retransmits && !p.a->arq->tx[1].queued);
    arq_request(p.a,1); assert(!p.a->count && p.a->arq_cache_miss==1);
    assert(arq_receive(p.b,3,0)==1); /* failed TUN injection stays missing */
    assert(p.b->arq->missing==2);
    p.b->now+=ARQ_CACHE_TTL; feedback(p.b);
    assert(!p.b->arq->missing && !p.b->arq->timer && !p.b->count);
    finish(&p); puts("PASS unbudgeted repair, repair expiry, local delivery failure and timer expiry");
}
static void unbudgeted_burst_test(void) {
    Pair p; init(&p);
    unsigned char payload[XT_MTU]={0}, out[2048];
    for (unsigned i=0;i<600;++i) {
        assert(enqueue(p.a,DATA,payload,sizeof(payload)) && flush(p.a,1));
        assert(xdtls_read(p.b->dtls,out,sizeof(out))==XT_HEADER+2+sizeof(payload));
    }
    uint64_t now=p.a->now;
    for (unsigned i=1;i<=600;++i) arq_request(p.a,(uint16_t)i);
    assert(p.a->count==XT_QUEUE-4 && p.a->arq->pending==600-(XT_QUEUE-4));
    unsigned received=0;
    while (p.a->count || p.a->arq->pending) {
        assert(flush(p.a,1));
        assert(xdtls_read(p.b->dtls,out,sizeof(out))==XT_HEADER+2+sizeof(payload));
        ++received; arq_retry_deferred(p.a);
    }
    assert(received==600 && p.a->arq_retransmits==600 && p.a->now==now && !p.a->arq_limited);
    arq_request(p.a,1); assert(!p.a->count); /* cooldown still deduplicates */
    p.a->now+=arq_cooldown(p.a->arq); arq_request(p.a,1);
    assert(p.a->count==1 && flush(p.a,1));
    assert(xdtls_read(p.b->dtls,out,sizeof(out))==XT_HEADER+2+sizeof(payload));
    finish(&p); puts("PASS 600 full-size repairs without clock advance, queue backpressure and cooldown");
}
static void wait_stats_test(void) {
    Pair p; init(&p);
    const unsigned waits[]={0,10,11,50,51,100,101,250,251,500,501,900};
    uint64_t total=0;
    for (unsigned i=0;i<sizeof(waits)/sizeof(waits[0]);++i) {
        p.ab.drop=1; send_data(p.a);
        p.a->count=XT_QUEUE-4; arq_request(p.a,(uint16_t)(i+1));
        assert(p.a->arq->pending==1 && p.a->count==XT_QUEUE-4);
        p.a->now+=waits[i]; total+=waits[i];
        p.a->count=0; arq_retry_deferred(p.a);
        assert(!p.a->arq->pending && p.a->count==1 && flush(p.a,1));
        assert(take_data(p.b,(uint16_t)(i+1))==1);
    }
    assert(p.a->arq_deferred_queued==12 && p.a->arq_defer_wait_max==900);
    assert(p.a->arq_defer_wait_sum==total);
    for (unsigned i=0;i<6;++i) assert(p.a->arq_defer_wait_bins[i]==2);
    p.ab.drop=1; send_data(p.a); p.a->count=XT_QUEUE-4; arq_request(p.a,13);
    p.a->now+=ARQ_CACHE_TTL; arq_retry_deferred(p.a);
    assert(!p.a->arq->pending && p.a->arq_deferred_expired==1);
    assert(p.a->arq_deferred_queued==12 && p.a->arq_defer_wait_sum==total);
    finish(&p); puts("PASS deferred wait histogram boundaries, sum and exclusion of abandoned requests");
}
static void queued_test(void) {
    Pair p; init(&p);
    assert(arq_receive(p.b,2,1)==1); p.b->now+=5; arq_tick(p.b);
    p.ba.block=1; assert(flush(p.b,1)); assert(xdtls_write_pending(p.b->dtls));
    unsigned char saved[XT_HEADER+2*ARQ_BATCH]; size_t len=p.b->queue[p.b->head].len;
    memcpy(saved,p.b->queue[p.b->head].bytes,len);
    assert(arq_receive(p.b,1,1)==1 && !p.b->arq->timer);
    assert(flush(p.b,1)); assert(!memcmp(saved,p.b->queue[p.b->head ? p.b->head-1 : XT_QUEUE-1].bytes,len));
    control(p.a); assert(p.b->arq_nacks==1 && !p.b->arq->timer);
    send_data(p.a); assert(take_data(p.b,1)==0);
    arq_request(p.a,1); p.ab.block=1; assert(flush(p.a,1));
    assert(xdtls_write_pending(p.a->dtls));
    p.a->now+=ARQ_CACHE_TTL;
    assert(flush(p.a,1)); assert(!xdtls_write_pending(p.a->dtls) && p.a->arq_retransmits==1);
    assert(take_data(p.b,1)==0);
    finish(&p); puts("PASS pending NACK/repair stays immutable across gap cancellation and expiry");
}
static void batch_test(void) {
    Pair p; init(&p);
    assert(arq_receive(p.b,600,1)==1 && p.b->arq->missing==599);
    feedback(p.b); control(p.a); assert(p.a->arq_requests==599);
    p.b->now+=20; feedback(p.b); control(p.a);
    assert(p.b->arq->rx[599].requested); /* all 599 gaps fit in one range; retries remain per-gap */
    p.b->now+=ARQ_CACHE_TTL; feedback(p.b); assert(!p.b->count && !p.b->arq->missing);
    unsigned char malformed[XT_HEADER+2*ARQ_BATCH+2]={1,ARQ_NACK,0,0};
    put32(malformed+4,1);
    assert(xdtls_write(p.a->dtls,malformed,XT_HEADER+1)==XT_HEADER+1); control(p.b);
    put32(malformed+4,2*ARQ_BATCH+2);
    assert(xdtls_write(p.a->dtls,malformed,sizeof(malformed))==sizeof(malformed)); control(p.b);
    malformed[1]=ARQ_MARK; put32(malformed+4,3);
    assert(xdtls_write(p.a->dtls,malformed,XT_HEADER+3)==XT_HEADER+3); control(p.b);
    assert(p.b->drop_frame==3);
    finish(&p); puts("PASS bounded batched feedback, fair rotation, mass expiry and malformed control rejection");
}
static void logging_test(void) {
    Pair p; init(&p); FILE *trace=tmpfile(); assert(trace);
    fflush(stdout); int saved=dup(fileno(stdout)); assert(saved>=0);
    assert(dup2(fileno(trace),fileno(stdout))>=0);
    arq_log(p.a,"disabled","value=1");
    /* An occupied newer slot proves overwrite, not just an unknown request.
     * Reports remain enabled without verbose tracing and are rate limited. */
    p.a->arq->sent=ARQ_WINDOW+1;
    p.a->arq->tx[1]=(ArqTx){.seq=ARQ_WINDOW+1,.born=p.a->now};
    arq_request(p.a,1); arq_request(p.a,1);
    assert(p.a->arq_cache_overwritten==2);
    memset(p.a->arq->tx,0,sizeof(p.a->arq->tx)); p.a->arq->sent=0;
    p.ca.arq_log=p.cb.arq_log=1; p.cb.server=1;
    send_data(p.a); assert(take_data(p.b,1)==1);
    p.ab.drop=1; send_data(p.a); send_data(p.a); assert(take_data(p.b,3)==1);
    p.ba.drop=1; feedback(p.b); /* exercise timer expiry after lost feedback */
    p.b->now+=20; feedback(p.b); control(p.a);
    assert(flush(p.a,1)); assert(take_data(p.b,2)==1);
    p.a->now+=200; feedback(p.a); control(p.b);
    p.ab.drop=1; send_data(p.a); /* tail gap is exposed by the watermark */
    p.a->now+=200; feedback(p.a); control(p.b); feedback(p.b); control(p.a);
    p.b->now+=ARQ_CACHE_TTL; feedback(p.b);
    uint16_t seqs[20]; for (unsigned i=0;i<20;++i) seqs[i]=(uint16_t)i;
    arq_log_batch(p.b,"preview",seqs,20);
    reset(p.b);
    fflush(stdout); assert(dup2(saved,fileno(stdout))>=0); close(saved);
    rewind(trace); char text[32768]; size_t n=fread(text,1,sizeof(text)-1,trace); text[n]=0; fclose(trace);
    const char *events[]={"gap_detect","gap_filled","timer_start","timer_expire","timer_arm","timer_cancel",
                          "nack_sent","nack_received","repair_queued","repair_sent","mark_sent","mark_received",
                          "gap_expired","session_clear"};
    for (unsigned i=0;i<sizeof(events)/sizeof(events[0]);++i) {
        char expected[64]; snprintf(expected,sizeof(expected),"event=%s ",events[i]);
        if (!strstr(text,expected)) fprintf(stderr,"Missing %s in trace:\n%s",expected,text);
        assert(strstr(text,expected));
    }
    assert(strstr(text,"trigger=data first=2 last=2 count=1"));
    assert(strstr(text,"trigger=watermark"));
    assert(strstr(text,"seqs=2 omitted=0"));
    assert(strstr(text,"delay_ms=20") && strstr(text,"delay_ms=50"));
    assert(strstr(text,"reason=gap_filled") && strstr(text,"reason=expired"));
    assert(strstr(text,"side=server") && strstr(text,"mono_ms=") && strstr(text,"omitted=4"));
    assert(!strstr(text,"event=disabled") && !strstr(text,"packet"));
    const char *report=strstr(text,"ARQ_CACHE_MISS side=client reason=overwritten requested_seq=1 requested_logical=1");
    assert(report && !strstr(report+1,"ARQ_CACHE_MISS"));
    finish(&p); puts("PASS optional ARQ logs trace real recovery/timer events, bound previews and omit payloads");
}
/* Simulate 25ms each way. Feedback and repairs cross the simulated link only
 * at their arrival time; the existing transport tests cover their decoding. */
static unsigned timed_recovery(int sampled, int lose_repair) {
    Pair p; init(&p);
    p.a->arq->srtt=p.a->arq->last_rtt=50;
    p.b->arq->srtt=sampled ? 50 : 0;
    p.ab.drop=1; send_data(p.a); send_data(p.a); assert(take_data(p.b,2)==1);
    unsigned arrivals[64], written=0, read=0, filled=0;
    unsigned repair_arrival=0;
    for (unsigned ms=0; ms<400 && !filled; ++ms) {
        p.a->now=p.b->now=10000+ms;
        arq_tick(p.b);
        if (p.b->count) {
            assert(written<64); p.ba.drop=1;
            assert(flush(p.b,XT_QUEUE)); arrivals[written++]=ms+25;
        }
        while (read<written && arrivals[read]==ms) {
            ++read; arq_request(p.a,1);
        }
        if (p.a->count) {
            p.ab.drop=1; assert(flush(p.a,XT_QUEUE));
            if (!lose_repair || p.a->arq_retransmits>1) repair_arrival=ms+25;
        }
        if (repair_arrival && repair_arrival==ms) {
            assert(arq_receive(p.b,1,1)==1); filled=ms;
        }
    }
    assert(filled && !p.b->arq->missing);
    assert(p.a->arq_retransmits==(lose_repair ? 2u : 1u));
    finish(&p); return filled;
}
static void feedback_rtt_test(void) {
    assert(arq_next_feedback_delay(20)==50);
    assert(arq_next_feedback_delay(50)==100);
    assert(arq_next_feedback_delay(100)==200);
    assert(arq_next_feedback_delay(200)==200);
    assert(timed_recovery(0,1)==220);
    assert(timed_recovery(1,1)==(ARQ_ADAPTIVE_FEEDBACK ? 125u : 220u));
    assert(timed_recovery(0,0)==50 && timed_recovery(1,0)==50);
    puts("PASS per-gap feedback snapshots RTT; healthy and lost-repair recovery");
}
static void ping_sampling_test(void) {
    Pair p; init(&p); Tunnel *a=p.a;
    p.ca.probe=p.cb.probe=0;
    /* First sample is immediate even before 20 seconds of system uptime. */
    a->now=p.b->now=100;
    ping_tick(a); assert(a->count==1 && a->last_ping==100);
    ping_tick(a); assert(a->count==1);
    assert(flush(a,XT_QUEUE)); control(p.b); assert(flush(p.b,XT_QUEUE));
    a->now=140; control(a);
    assert(a->arq->srtt==40 && !a->arq->ping_wait);
    /* Control traffic does not enable fast sampling. */
    a->now=1100; ping_tick(a); assert(!a->count);
    a->arq->last_data=a->now;
    ping_tick(a); assert(a->count==1 && a->last_ping==1100);
    assert(flush(a,XT_QUEUE));
    a->now=2099; ping_tick(a); assert(!a->count);
    a->now=2100; ping_tick(a); assert(a->count==1);
    assert(flush(a,XT_QUEUE));
    /* Receive-only traffic also enables fast sampling. */
    a->arq->last_data=0; a->arq->last_rx_data=3100; a->now=3100;
    ping_tick(a); assert(a->count==1); assert(flush(a,XT_QUEUE));
    a->now=8100; ping_tick(a); assert(!a->count);
    a->now=23099; ping_tick(a); assert(!a->count);
    a->now=23100; ping_tick(a); assert(a->count==1);
    assert(flush(a,XT_QUEUE));
    /* Non-ARQ tunnels retain the idle keepalive period. */
    Arq *saved=a->arq; a->arq=NULL; a->now=24100;
    ping_tick(a); assert(!a->count); a->arq=saved;
    p.ca.probe=1; ping_tick(a); assert(a->count==1);
    assert(flush(a,XT_QUEUE));
    a->active=0; a->now+=20000; ping_tick(a); assert(!a->count);
    finish(&p); puts("PASS immediate RTT probe, 1s bidirectional activity sampling and 20s idle keepalive");
}
static void cumulative_ack_test(void) {
    Pair p; init(&p);
    send_data(p.a); assert(take_data(p.b,1)==1);
    send_data(p.a); assert(take_data(p.b,2)==1);
    assert(p.b->arq->received_through==2);
    /* A receive-only peer sends ACKs, with no outbound DATA of its own. */
    p.b->arq->last_rx_data=p.b->now;
    p.b->now+=ARQ_MARK_INTERVAL;
    arq_request(p.a,1); assert(p.a->count==1);
    arq_tick(p.b); assert(p.b->count==1);
    assert(flush(p.b,XT_QUEUE)); control(p.a);
    assert(p.a->arq->peer_received==2 && !p.a->arq->tx[1].len);
    assert(flush(p.a,XT_QUEUE) && !p.a->arq_retransmits);
    arq_request(p.a,1); assert(!p.a->count);
    arq_ack(p.a,1); arq_ack(p.a,3); assert(p.a->arq->peer_received==2);
    /* Pending queue-blocked requests are removed on cumulative ACK. */
    send_data(p.a); p.a->count=XT_QUEUE-4;
    arq_request(p.a,3); assert(p.a->arq->pending==1);
    arq_ack(p.a,3); assert(!p.a->arq->pending); p.a->count=0;
    arq_request(p.a,3); assert(!p.a->count);
    /* Out-of-order receipt cannot acknowledge the missing packet. */
    assert(arq_receive(p.b,4,1)==1 && p.b->arq->received_through==2);
    assert(arq_receive(p.b,3,1)==1 && p.b->arq->received_through==4);
    p.b->dev=(XtDevice *)p.b;
    assert(arq_receive(p.b,6,1)==1);
    p.b->now+=ARQ_CACHE_TTL; arq_drain(p.b,0);
    assert(p.b->arq->received_through==4); /* TTL skip is not receipt */
    /* Full logical ACKs do not alias on 16-bit wire sequence rollover. */
    memset(p.b->arq,0,sizeof(*p.b->arq));
    p.b->arq->high=p.b->arq->delivered=p.b->arq->received_through=65534;
    assert(arq_receive(p.b,0,1)==1 && p.b->arq->received_through==65534);
    assert(arq_receive(p.b,65535,1)==1 && p.b->arq->received_through==65536);
    p.a->arq->sent=65537; p.a->arq->peer_received=65536;
    arq_request(p.a,0); assert(!p.a->count);
    arq_ack(p.a,1); assert(p.a->arq->peer_received==65536);
    finish(&p);
    puts("PASS cumulative MARK ACK, receive-only feedback, queued/pending cancellation, stale NACK and rollover");
}
static void packed_nack_test(void) {
    uint16_t ids[ARQ_WINDOW], decoded[ARQ_WINDOW];
    unsigned char encoded[ARQ_NACK_BYTES];
    for (unsigned i=0; i<3000; ++i) ids[i]=(uint16_t)(65000+i);
    unsigned n=arq_nack_encode(ids,3000,encoded);
    assert(n==5 && encoded[0]==ARQ_RANGE && be16(encoded+1)==65000 && be16(encoded+3)==3000);
    assert(arq_nack_decode(ARQ_NACK_PACKED,encoded,n,decoded)==3000);
    assert(!memcmp(ids,decoded,3000*sizeof(*ids)));
    for (unsigned i=0; i<100; ++i) ids[i]=(uint16_t)(65530+2*i);
    n=arq_nack_encode(ids,100,encoded);
    assert(n==30 && encoded[0]==ARQ_BITMAP && be16(encoded+3)==199);
    assert(arq_nack_decode(ARQ_NACK_PACKED,encoded,n,decoded)==100);
    assert(!memcmp(ids,decoded,100*sizeof(*ids)));
    ids[0]=65534; ids[1]=0; ids[2]=3;
    n=arq_nack_encode(ids,3,encoded);
    assert(n==6 && encoded[0]==ARQ_BITMAP && encoded[5]==0x25);
    assert(arq_nack_decode(ARQ_NACK_PACKED,encoded,n,decoded)==3 && !memcmp(ids,decoded,6));
    ids[0]=100; ids[1]=8000;
    n=arq_nack_encode(ids,2,encoded);
    assert(n==5 && encoded[0]==ARQ_IDS);
    assert(arq_nack_decode(ARQ_NACK_PACKED,encoded,n,decoded)==2 && !memcmp(ids,decoded,4));
    for (unsigned i=0; i<ARQ_WINDOW; ++i) ids[i]=(uint16_t)(65530+i);
    n=arq_nack_encode(ids,ARQ_WINDOW,encoded);
    assert(n==5 && encoded[0]==ARQ_RANGE);
    assert(arq_nack_decode(ARQ_NACK_PACKED,encoded,n,decoded)==ARQ_WINDOW);
    assert(!memcmp(ids,decoded,sizeof(ids)));
    /* Random dense/sparse sets, wire rollover and byte-cap truncation. */
    unsigned rng=7;
    for (unsigned round=0; round<200; ++round) {
        unsigned count=0;
        for (unsigned i=0; i<ARQ_WINDOW; ++i) {
            rng=1664525u*rng+1013904223u;
            if (rng%100 < (round%99)+1) ids[count++]=(uint16_t)(65000+i);
        }
        n=arq_nack_encode(ids,count,encoded);
        assert(n && n<=ARQ_NACK_BYTES);
        unsigned got=arq_nack_decode(ARQ_NACK_PACKED,encoded,n,decoded);
        assert(got && got<=count && !memcmp(ids,decoded,got*sizeof(*ids)));
    }
    unsigned char bad[]={ARQ_BITMAP,0,1,0,1,0x80};
    assert(!arq_nack_decode(ARQ_NACK_PACKED,bad,sizeof(bad),decoded)); /* padding bits */
    bad[5]=0; assert(!arq_nack_decode(ARQ_NACK_PACKED,bad,sizeof(bad),decoded)); /* empty */
    bad[5]=1; assert(!arq_nack_decode(ARQ_NACK_PACKED,bad,sizeof(bad)-1,decoded));
    bad[3]=bad[4]=0; assert(!arq_nack_decode(ARQ_NACK_PACKED,bad,sizeof(bad),decoded));
    bad[0]=99; assert(!arq_nack_decode(ARQ_NACK_PACKED,bad,sizeof(bad),decoded));
    /* Real feedback starts at the earliest due logical gap across rollover. */
    Pair p; init(&p);
    p.b->arq->high=p.b->arq->received_through=p.b->arq->delivered=65533;
    p.a->arq->sent=65540;
    assert(arq_receive(p.b,4,1)==1);
    p.b->now+=ARQ_REORDER; arq_tick(p.b);
    p.ba.block=1; assert(flush(p.b,1));
    unsigned char *wire=p.b->queue[p.b->head].bytes;
    assert(wire[1]==ARQ_NACK_PACKED && wire[8]==ARQ_RANGE && be16(wire+9)==65534 && be16(wire+11)==6);
    assert(flush(p.b,1)); control(p.a); assert(p.a->arq_requests==6);
    finish(&p);
    /* Validate the whole packed frame before issuing any repair requests. */
    init(&p);
    const unsigned char malformed[][6]={
        {ARQ_BITMAP,0,1,0,1,0x81}, /* valid first bit but invalid padding */
        {ARQ_RANGE,0,1,0,0,0},    /* zero span */
        {ARQ_RANGE,0,1,0x20,1,0}, /* outside receive window */
        {ARQ_IDS,0,1,0,0,0},      /* odd ID payload length */
        {99,0,0,0,0,0}
    };
    for (unsigned i=0; i<sizeof(malformed)/sizeof(*malformed); ++i) {
        unsigned char frame[XT_HEADER+6]={1,ARQ_NACK_PACKED,0,0};
        put32(frame+4,6); memcpy(frame+XT_HEADER,malformed[i],6);
        assert(xdtls_write(p.b->dtls,frame,sizeof(frame))==(int)sizeof(frame)); control(p.a);
        assert(p.a->drop_frame==i+1 && !p.a->arq_requests && !p.a->count);
    }
    finish(&p);
    /* A near-full sparse window spans two feedbacks without starving its tail. */
    init(&p);
    assert(arq_receive(p.b,(uint16_t)(ARQ_WINDOW-1),1)==1);
    assert(arq_receive(p.b,2,1)==1);
    feedback(p.b); control(p.a);
    assert(p.a->arq_requests==8151 && !p.b->arq->rx[(ARQ_WINDOW-2)%ARQ_WINDOW].requested);
    for (unsigned i=0; i<ARQ_WINDOW/8152+1 && !p.b->arq->rx[ARQ_WINDOW-2].requested; ++i) {
        p.b->now+=ARQ_FEEDBACK_GAP; feedback(p.b); control(p.a);
    }
    assert(p.b->arq->rx[ARQ_WINDOW-2].requested && p.a->arq_requests==ARQ_WINDOW-3);
    finish(&p);
    puts("PASS packed NACK list/range/bitmap, rollover, malformed payloads, byte bounds and tail fairness");
}
static void mark_feedback_test(void) {
    Pair p; init(&p);
    p.ab.drop=4;
    for (unsigned i=0; i<4; ++i) send_data(p.a);
    assert(arq_receive(p.b,1,1)==1 && arq_receive(p.b,2,1)==1 && arq_receive(p.b,4,1)==1);
    p.b->arq->last_rx_data=p.b->now;
    p.b->now+=ARQ_MARK_INTERVAL; arq_tick(p.b);
    assert(p.b->count==2); /* MARK first, independent NACK behind it */
    arq_request(p.a,1); assert(p.a->count==1);
    p.ba.block=1; assert(flush(p.b,XT_QUEUE));
    assert(xdtls_write_pending(p.b->dtls));
    unsigned char saved[XT_HEADER+12+ARQ_NACK_BYTES];
    size_t n=p.b->queue[p.b->head].len;
    assert(p.b->queue[p.b->head].bytes[1]==ARQ_MARK_STATE && n>XT_HEADER+12);
    memcpy(saved,p.b->queue[p.b->head].bytes,n);
    /* A gap filling during WANT_WRITE cannot mutate the queued MARK. */
    assert(arq_receive(p.b,3,1)==1);
    unsigned head=p.b->head;
    assert(flush(p.b,XT_QUEUE));
    assert(!memcmp(saved,p.b->queue[head].bytes,n));
    assert(!p.b->count && p.b->arq_nacks==1 && !p.b->arq->nack_queued);
    control(p.a);
    assert(p.a->arq->peer_received==2 && p.a->arq_requests==1);
    assert(flush(p.a,XT_QUEUE) && p.a->arq_retransmits==1); /* only gap 3 */
    /* An invalid embedded request cannot partially apply its ACK. */
    unsigned char bad[XT_HEADER+12]={1,ARQ_MARK,0,0};
    put32(bad+4,12); put32(bad+10,4);
    bad[14]=ARQ_BITMAP; put16(bad+15,3); put16(bad+17,1); bad[19]=0x81;
    assert(xdtls_write(p.b->dtls,bad,sizeof(bad))==(int)sizeof(bad)); control(p.a);
    assert(p.a->drop_frame==1 && p.a->arq->peer_received==2 && p.a->arq_requests==1);
    finish(&p);
    /* With no write stall, MARK advances backoff and cancels redundant NACK. */
    init(&p); assert(arq_receive(p.b,2,1)==1);
    p.b->arq->last_rx_data=p.b->now; p.b->now+=ARQ_MARK_INTERVAL;
    arq_tick(p.b); assert(p.b->count==2);
    assert(flush(p.b,XT_QUEUE)); control(p.a);
    assert(p.b->arq_nacks==1 && p.a->arq_requests==1);
    assert(p.b->arq->rx[1].requested && p.b->arq->rx[1].feedback_due==p.b->now+ARQ_INITIAL);
    finish(&p);
    puts("PASS MARK piggyback ACK/NACK, shared backoff, duplicate cancellation, immutable retries and atomic validation");
}
static void unavailable_mark_test(void) {
    Pair p; init(&p); p.ab.drop=2;
    send_data(p.a); send_data(p.a);
    p.b->dev=(XtDevice *)p.b; delivered_count=0;
    assert(arq_store_packet(p.b,2,"B",1)==1 && p.b->arq->missing==1);
    p.a->arq->tx[1].born=p.a->now-ARQ_CACHE_TTL;
    p.a->now+=ARQ_MARK_INTERVAL; p.b->now=p.a->now;
    arq_tick(p.b); assert(p.b->arq->nack_queued);
    arq_tick(p.a); assert(flush(p.a,XT_QUEUE)); control(p.b);
    assert(p.b->arq->peer_unavailable==1 && !p.b->arq->missing);
    assert(p.b->arq_expired_remote==1 && !p.b->arq_expired_ttl);
    assert(delivered_count==1 && delivered_bytes[0]=='B' && !p.b->arq->buffered);
    assert(!p.b->arq->received_through); /* abandonment is never receipt */
    assert(flush(p.b,XT_QUEUE) && !p.b->arq_nacks && !p.b->arq->nack_queued);
    assert(arq_store_packet(p.b,1,"A",1)==0 && delivered_count==1);
    arq_expire_remote(p.b,0); arq_expire_remote(p.b,3);
    assert(p.b->arq->peer_unavailable==1 && p.b->arq_expired_remote==1);
    /* A live prefix entry prevents a later missing/cleared slot being declared lost. */
    assert(arq_unavailable(p.a)==1);
    p.a->arq->tx[2].born=p.a->now-ARQ_CACHE_TTL;
    assert(arq_unavailable(p.a)==2);
    /* Lost final notices are repeated after the last original's cache TTL. */
    p.a->now=p.a->arq->last_data+ARQ_CACHE_TTL+1; p.ab.drop=1;
    arq_tick(p.a); assert(p.a->count && flush(p.a,XT_QUEUE)); control(p.b);
    assert(p.b->arq->peer_unavailable==1);
    p.a->now+=ARQ_MARK_INTERVAL;
    arq_tick(p.a); assert(p.a->count && flush(p.a,XT_QUEUE)); control(p.b);
    assert(p.b->arq->peer_unavailable==2 && !p.b->arq->received_through);
    /* Validate all state fields and embedded feedback before mutating state. */
    unsigned char bad[XT_HEADER+12]={1,ARQ_MARK_STATE,0,0}; put32(bad+4,12);
    put32(bad+8,2); put32(bad+16,3);
    assert(xdtls_write(p.a->dtls,bad,sizeof(bad))==(int)sizeof(bad)); control(p.b);
    assert(p.b->drop_frame==1 && p.b->arq->peer_unavailable==2);
    finish(&p);
    init(&p); delivered_count=0; p.b->dev=(XtDevice *)p.b;
    p.a->arq->sent=p.a->arq->next=65537;
    p.a->arq->tx[1]=(ArqTx){.seq=65537,.born=p.a->now,.len=8};
    p.a->arq->unavailable=65534;
    p.b->arq->high=p.b->arq->delivered=p.b->arq->received_through=65534;
    assert(arq_store_packet(p.b,1,"D",1)==1 && p.b->arq->missing==2);
    p.a->arq->last_data=p.a->now; p.a->now+=200; p.b->now=p.a->now;
    arq_tick(p.a); assert(flush(p.a,XT_QUEUE)); control(p.b);
    assert(p.b->arq->peer_unavailable==65536 && !p.b->arq->missing && delivered_count==1);
    assert(p.b->arq->received_through==65534);
    arq_expire_remote(p.b,1); assert(p.b->arq->peer_unavailable==65536);
    /* Ring overwrite advances only through entries that can no longer be cached. */
    memset(p.a->arq,0,sizeof(*p.a->arq));
    p.a->arq->sent=ARQ_WINDOW+3;
    p.a->arq->tx[4]=(ArqTx){.seq=4,.born=p.a->now,.len=8};
    assert(arq_unavailable(p.a)==3);
    /* Full logical rollover must reset the session, never alias old IDs. */
    p.a->arq->next=UINT32_MAX;
    assert(!enqueue(p.a,DATA,"X",1) && p.a->arq->next==UINT32_MAX && p.a->records==(1u<<24));
    p.b->arq->high=UINT32_MAX-1; uint32_t logical;
    assert(arq_advance(p.b,65535,&logical,1)==-1);
    finish(&p);
    puts("PASS unavailable cache prefix MARK, prompt release, no false ACK, repeat/stale validation, wire rollover and logical reset");
}
static void adaptive_feedback_test(void) {
    Pair p; init(&p); Tunnel *b=p.b;
    if (ARQ_ADAPTIVE_FEEDBACK) {
        b->arq->srtt=b->arq->last_rtt=80;
        assert(arq_reorder_grace(b->arq)==0 && arq_initial_feedback(b->arq)==120);
        assert(arq_receive(b,2,1)==1);
        arq_tick(b); assert(b->count==1 && b->arq->nack_due==b->now);
        assert(flush(b,XT_QUEUE)); control(p.a);
        assert(arq_receive(b,1,1)==1);
        assert(!b->arq->missing && b->arq_nacks==1);
        assert(arq_receive(b,4,1)==1);
        feedback(b); control(p.a);
        assert(b->arq_nacks==2 && b->arq->rx[3].feedback_due==b->now+120);
        uint64_t old_due=b->arq->rx[3].feedback_due;
        b->arq->ping_wait=1; b->arq->ping_token=7; b->arq->ping_sent=b->now-400;
        arq_pong(b,7);
        assert(b->arq->rx[3].feedback_due==old_due); /* no deadline postponement */
        assert(arq_receive(b,6,1)==1 && b->arq->rx[5].feedback_due==b->now);
        assert(b->arq->rx[5].delay==ARQ_BACKOFF_MAX);
        assert(b->arq->rx[3].feedback_due==old_due);
        b->arq->srtt=b->arq->last_rtt=1;
        assert(arq_reorder_grace(b->arq)==0 && arq_initial_feedback(b->arq)==20);
        b->arq->srtt=b->arq->last_rtt=5000;
        assert(arq_reorder_grace(b->arq)==0 && arq_initial_feedback(b->arq)==200);
        assert(arq_next_feedback_delay(75)==150 && arq_next_feedback_delay(150)==200);
    }
    finish(&p);
    init(&p); b=p.b; b->dev=(XtDevice *)b; delivered_count=0;
    assert(arq_store_packet(b,2,"B",1)==1 && !b->arq_delivery_count);
    b->now+=37; assert(arq_store_packet(b,1,"A",1)==1);
    assert(delivered_count==2 && b->arq_delivery_count==2);
    assert(b->arq_delivery_wait_sum==37 && b->arq_delivery_wait_max==37);
    assert(b->arq_delivery_wait_bins[0]==1 && b->arq_delivery_wait_bins[2]==1);
    assert(arq_store_packet(b,2,"B",1)==0 && b->arq_delivery_count==2);
    delivery_blocked=1; assert(arq_store_packet(b,3,"C",1)==1);
    assert(b->arq_delivery_count==2);
    b->now+=50; delivery_blocked=0; arq_drain(b,0);
    assert(b->arq_delivery_count==3 && b->arq_delivery_wait_sum==87 && b->arq_delivery_wait_max==50);
    assert(b->arq_delivery_wait_bins[2]==2);
    assert(arq_store_packet(b,5,"E",1)==1);
    b->now+=ARQ_ORDER_WAIT; arq_drain(b,0);
    ++b->now; assert(arq_store_packet(b,4,"D",1)==1);
    assert(b->arq_delivery_count==5 && b->arq_delivery_wait_sum==87+ARQ_ORDER_WAIT);
    assert(b->arq_delivery_wait_bins[0]==2 && b->arq_delivery_wait_bins[5]==1);
    assert(b->arq_delivery_wait_max==ARQ_ORDER_WAIT);
    finish(&p);
    puts("PASS immediate fresh gaps, adaptive retries, immutable deadlines and real delivery wait accounting");
}
int main(void) {
    adaptive_feedback_test();
    unavailable_mark_test();
    mark_feedback_test();
    packed_nack_test();
    cumulative_ack_test();
    ordered_delivery_test();
    separate_order_deadline_test();
    encrypted_order_test();
    independent_batch_test(); long_recovery_test();
    timer_test(); recovery_test(); priority_test(); reorder_test(); watermark_test(); wrap_test(); bounds_test(); queued_test(); batch_test();
    unbudgeted_burst_test(); wait_stats_test(); logging_test(); ping_sampling_test(); feedback_rtt_test();
    puts("ALL ARQ TESTS PASSED"); return 0;
}
