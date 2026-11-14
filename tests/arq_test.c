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
    assert(arq_store_packet(t, 1, "A", 1) == 1);
    assert(delivered_count == 2 && !memcmp(delivered_bytes,"AB",2));
    assert(!t->arq->buffered && !t->arq->missing);
    assert(arq_store_packet(t, 4, "D", 1) == 1);
    t->now += ARQ_TTL-1; arq_drain(t,0); assert(delivered_count == 2);
    ++t->now; arq_drain(t,0);
    assert(delivered_count == 3 && delivered_bytes[2] == 'D' && t->arq_order_skips == 1);
    assert(arq_store_packet(t, 3, "C", 1) == 0);
    delivery_blocked = 1;
    assert(arq_store_packet(t, 5, "E", 1) == 1 && delivered_count == 3);
    delivery_blocked = 0; arq_drain(t,0);
    assert(delivered_count == 4 && delivered_bytes[3] == 'E');
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
    t->now+=ARQ_TTL; arq_drain(t,0);
    assert(!t->arq->buffered && t->drop_tun_write==1 && delivered_count==2);
    delivery_blocked=0;
    free(t->arq); free(t);
    puts("PASS ordered delivery, deduplication, timeout, local retry and ring eviction");
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
    p->a->arq->credit=p->b->arq->credit=4*XT_MTU_MAX;
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
    finish(&p);
    puts("PASS real DTLS receive path holds later IP packet until repair arrives");
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
    const unsigned times[]={5,25,65,145,305,465};
    arq_tick(b); assert(b->arq->nack_due==10005 && !b->count);
    for (unsigned i=0;i<sizeof(times)/sizeof(times[0]);++i) {
        if (i) { b->now=10000+times[i]-1; arq_tick(b); assert(!b->count); }
        b->now=10000+times[i]; feedback(b); control(p.a);
        assert(b->arq_nacks==i+1 && b->arq->timer);
    }
    /* A new gap gets its own grace period while old gaps keep their backoff. */
    uint64_t due=b->arq->nack_due;
    assert(arq_receive(b,4,1)==1); arq_tick(b); assert(b->arq->nack_due==b->now+5);
    assert(b->arq->rx[1].feedback_due==due);
    uint64_t requests=p.a->arq_requests;
    b->now+=5; feedback(b); control(p.a);
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
    finish(&p); puts("PASS 5ms grace, per-gap 20/40/80/160ms backoff, new-gap independence and cancellation");
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
    /* Repeated 1ms reordering must not emit any NACK or start a repair. */
    for (unsigned seq=1; seq<1000; seq+=2) {
        assert(arq_receive(b,(uint16_t)(seq+1),1)==1);
        arq_tick(b); assert(!b->count && b->arq->nack_due==b->now+ARQ_REORDER);
        ++b->now; assert(arq_receive(b,(uint16_t)seq,1)==1);
        arq_tick(b); assert(!b->count && !b->arq->timer);
        b->now+=9;
    }
    assert(!b->arq_nacks && !b->arq->missing);
    finish(&p);
    init(&p); b=p.b;
    assert(arq_receive(b,2,1)==1); arq_tick(b);
    b->now+=ARQ_REORDER-1; arq_tick(b); assert(!b->count);
    ++b->now; arq_tick(b); assert(b->count==1);
    /* A new gap appears while old feedback is queued. Refreshing that
     * message must not request the younger gap before its own grace ends. */
    assert(arq_receive(b,4,1)==1);
    assert(flush(b,XT_QUEUE)); control(p.a);
    assert(p.a->arq_requests==1 && b->arq->rx[1].requested && !b->arq->rx[3].requested);
    assert(b->arq->nack_due==b->now+ARQ_REORDER);
    uint64_t old_due=b->arq->rx[1].feedback_due;
    b->now+=ARQ_REORDER; feedback(b); control(p.a);
    assert(p.a->arq_requests==2 && b->arq->rx[3].requested);
    assert(b->arq->rx[1].feedback_due==old_due && b->arq->nack_due==old_due);
    finish(&p); puts("PASS 500 short reorders without NACK and queued feedback preserves new-gap grace");
}
static void watermark_test(void) {
    Pair p; init(&p); p.ab.drop=1; send_data(p.a);
    p.a->now+=199; arq_tick(p.a); assert(!p.a->count);
    ++p.a->now; feedback(p.a); control(p.b); assert(p.b->arq->missing==1);
    feedback(p.b); control(p.a); assert(p.a->count==1 && flush(p.a,1));
    assert(take_data(p.b,1)==1); /* no later DATA was needed */
    p.a->now+=200; feedback(p.a); control(p.b); assert(!p.b->arq->missing);
    p.a->now=11200; arq_tick(p.a); assert(!p.a->count); /* stop after cache lifetime */
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
    arq_request(p.a,1); assert(!p.a->count && p.a->arq_cache_miss);
    finish(&p); puts("PASS 70,000 DATA messages, 16-bit rollover including lost zero, bounded cache and ambiguous jump rejection");
}
static void bounds_test(void) {
    Pair p; init(&p); send_data(p.a); assert(take_data(p.b,1)==1);
    p.a->arq->credit=0; arq_request(p.a,1); assert(!p.a->count && p.a->arq_limited==1);
    p.a->arq->credit=10000; arq_request(p.a,1); assert(p.a->count==1);
    p.a->now+=ARQ_TTL; assert(flush(p.a,1));
    assert(!p.a->count && !p.a->arq_retransmits && !p.a->arq->tx[1].queued);
    arq_request(p.a,1); assert(!p.a->count && p.a->arq_cache_miss==1);
    assert(arq_receive(p.b,3,0)==1); /* failed TUN injection stays missing */
    assert(p.b->arq->missing==2);
    p.b->now+=ARQ_TTL; feedback(p.b);
    assert(!p.b->arq->missing && !p.b->arq->timer && !p.b->count);
    finish(&p); puts("PASS byte budget, repair expiry, local delivery failure and timer expiry");
}
static void burst_credit_test(void) {
    Pair p; init(&p);
    unsigned char payload[XT_MTU]={0}, out[2048];
    size_t initial=p.a->arq->credit;
    for (unsigned i=0;i<600;++i) {
        assert(enqueue(p.a,DATA,payload,sizeof(payload)) && flush(p.a,1));
        assert(xdtls_read(p.b->dtls,out,sizeof(out))==XT_HEADER+2+sizeof(payload));
        if (!i) assert(p.a->arq->credit==initial+(XT_HEADER+2+sizeof(payload))/4);
    }
    assert(p.a->arq->credit==ARQ_CREDIT_MAX);
    /* A quiet period earns enough credit for a burst larger than the old cap. */
    for (unsigned seq=1;seq<=100;++seq) {
        arq_request(p.a,(uint16_t)seq);
        assert(p.a->count==1 && flush(p.a,1));
        assert(xdtls_read(p.b->dtls,out,sizeof(out))==XT_HEADER+2+sizeof(payload));
    }
    assert(p.a->arq_retransmits==100 && !p.a->arq_limited && !p.a->arq->pending);
    assert(p.a->arq->credit==ARQ_CREDIT_MAX-100*(XT_HEADER+2+sizeof(payload)));
    arq_request(p.a,101); assert(p.a->count==1);
    p.a->arq->credit=ARQ_CREDIT_MAX; p.a->now+=ARQ_TTL;
    assert(flush(p.a,1) && p.a->arq->credit==ARQ_CREDIT_MAX);
    assert(!p.a->count && p.a->arq_retransmits==100);
    finish(&p); puts("PASS larger earned burst allowance, unchanged quarter-rate earning and bounded expiry refund");
}
static void wait_stats_test(void) {
    Pair p; init(&p);
    const unsigned waits[]={0,10,11,50,51,100,101,250,251,500,501,900};
    uint64_t total=0;
    for (unsigned i=0;i<sizeof(waits)/sizeof(waits[0]);++i) {
        p.ab.drop=1; send_data(p.a);
        p.a->arq->credit=0; arq_request(p.a,(uint16_t)(i+1));
        assert(p.a->arq->pending==1 && !p.a->count);
        p.a->now+=waits[i]; total+=waits[i];
        p.a->arq->credit=ARQ_CREDIT_MAX; arq_retry_deferred(p.a);
        assert(!p.a->arq->pending && p.a->count==1 && flush(p.a,1));
        assert(take_data(p.b,(uint16_t)(i+1))==1);
    }
    assert(p.a->arq_deferred_queued==12 && p.a->arq_defer_wait_max==900);
    assert(p.a->arq_defer_wait_sum==total);
    for (unsigned i=0;i<6;++i) assert(p.a->arq_defer_wait_bins[i]==2);
    p.ab.drop=1; send_data(p.a); p.a->arq->credit=0; arq_request(p.a,13);
    p.a->now+=ARQ_TTL; arq_retry_deferred(p.a);
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
    p.a->now+=ARQ_TTL;
    assert(flush(p.a,1)); assert(!xdtls_write_pending(p.a->dtls) && p.a->arq_retransmits==1);
    assert(take_data(p.b,1)==0);
    finish(&p); puts("PASS pending NACK/repair stays immutable across gap cancellation and expiry");
}
static void batch_test(void) {
    Pair p; init(&p);
    assert(arq_receive(p.b,600,1)==1 && p.b->arq->missing==599);
    feedback(p.b); control(p.a); assert(p.a->arq_requests==ARQ_BATCH);
    p.b->now+=20; feedback(p.b); control(p.a);
    assert(p.b->arq->rx[599].requested); /* later gaps are not starved by the first batch */
    p.b->now+=ARQ_TTL; feedback(p.b); assert(!p.b->count && !p.b->arq->missing);
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
    p.ca.arq_log=p.cb.arq_log=1; p.cb.server=1;
    send_data(p.a); assert(take_data(p.b,1)==1);
    p.ab.drop=1; send_data(p.a); send_data(p.a); assert(take_data(p.b,3)==1);
    p.ba.drop=1; feedback(p.b); /* exercise timer expiry after lost feedback */
    p.b->now+=20; feedback(p.b); control(p.a);
    assert(flush(p.a,1)); assert(take_data(p.b,2)==1);
    p.a->now+=200; feedback(p.a); control(p.b);
    p.ab.drop=1; send_data(p.a); /* tail gap is exposed by the watermark */
    p.a->now+=200; feedback(p.a); control(p.b); feedback(p.b); control(p.a);
    p.b->now+=ARQ_TTL; feedback(p.b);
    unsigned char seqs[40]; for (unsigned i=0;i<20;++i) put16(seqs+2*i,(uint16_t)i);
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
    assert(strstr(text,"delay_ms=20") && strstr(text,"delay_ms=40"));
    assert(strstr(text,"reason=gap_filled") && strstr(text,"reason=expired"));
    assert(strstr(text,"side=server") && strstr(text,"mono_ms=") && strstr(text,"omitted=4"));
    assert(!strstr(text,"event=disabled") && !strstr(text,"packet"));
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
    Arq a={0};
    assert(arq_feedback_delay(&a,160)==160);
    a.srtt=1; assert(arq_feedback_delay(&a,160)==20);
    a.srtt=51; assert(arq_feedback_delay(&a,160)==26);
    assert(arq_feedback_delay(&a,20)==20);
    a.srtt=1000; assert(arq_feedback_delay(&a,160)==160);
    assert(timed_recovery(0,1)==195);
    assert(timed_recovery(1,1)==150);
    assert(timed_recovery(0,0)==55 && timed_recovery(1,0)==55);
    puts("PASS RTT-bounded feedback: lost repair recovers in 150ms vs 195ms; healthy repair unchanged");
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
int main(void) {
    ordered_delivery_test();
    encrypted_order_test();
    timer_test(); recovery_test(); priority_test(); reorder_test(); watermark_test(); wrap_test(); bounds_test(); queued_test(); batch_test();
    burst_credit_test(); wait_stats_test(); logging_test(); ping_sampling_test(); feedback_rtt_test();
    puts("ALL ARQ TESTS PASSED"); return 0;
}
