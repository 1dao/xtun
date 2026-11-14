/* Exercise the real reader/queue/wakeup with a fake Wintun packet source.
 * No adapter, route, driver or administrator access is required. */
#include "../src/platform.c"
#include "xpoll.h"
#include <assert.h>

volatile sig_atomic_t xt_stop;
typedef struct {
    HANDLE ready;
    volatile LONG pending, released, fail;
    BYTE packet;
} Source;
static HANDLE WINAPI mock_event(void *p) { return ((Source *)p)->ready; }
static BYTE *WINAPI mock_receive(void *p, DWORD *n) {
    Source *s = p;
    if (s->fail) { SetLastError(ERROR_INVALID_DATA); return NULL; }
    if (!s->pending) { SetLastError(ERROR_NO_MORE_ITEMS); return NULL; }
    InterlockedDecrement(&s->pending);
    s->packet = (BYTE)s->released; *n = 1;
    return &s->packet;
}
static void WINAPI mock_release(void *p, BYTE *packet) {
    (void)packet; InterlockedIncrement(&((Source *)p)->released);
}
static void WINAPI mock_end(void *p) { (void)p; }
static void push(Source *s, LONG n) {
    InterlockedExchangeAdd(&s->pending, n); SetEvent(s->ready);
}
static DWORD WINAPI delayed_push(void *p) { Sleep(25); push(p, 1); return 0; }
static void released(Source *s, LONG target) {
    uint64_t deadline = xt_now() + 2000;
    while (s->released < target && xt_now() < deadline) Sleep(1);
    assert(s->released == target);
}
int main(void) {
    assert(!socket_init()); assert(!xpoll_init());
    Source s = {0}; s.ready = CreateEventW(NULL, FALSE, FALSE, NULL); assert(s.ready);
    XtDevice *d = calloc(1, sizeof(*d)); assert(d);
    d->wake[0] = d->wake[1] = INVALID_SOCKET_VAL;
    InitializeCriticalSection(&d->lock);
    d->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    d->room = CreateEventW(NULL, FALSE, FALSE, NULL);
    assert(d->stop && d->room);
    char error[256]; assert(wake_init(d, error));
    d->session = &s; d->GetReadWaitEvent = mock_event;
    d->ReceivePacket = mock_receive; d->ReleaseReceivePacket = mock_release;
    d->EndSession = mock_end;
    d->thread = CreateThread(NULL, 0, reader, d, 0, NULL); assert(d->thread);
    SOCKET_T fd = xt_device_fd(d);
    assert(!xpoll_add_event(fd, XPOLL_READABLE | XPOLL_ERROR, NULL, NULL, NULL, NULL));
    assert(xpoll_poll(0) == 0);
    HANDLE producer = CreateThread(NULL, 0, delayed_push, &s, 0, NULL); assert(producer);
    assert(xpoll_poll(1000) > 0); /* a cross-thread TUN arrival interrupts the wait */
    assert(WaitForSingleObject(producer, 2000) == WAIT_OBJECT_0); CloseHandle(producer);
    BYTE packet;
    assert(xt_device_read(d, &packet, 1) == 1 && packet == 0);
    assert(xpoll_poll(0) == 0);
    push(&s, 64); released(&s, 65);
    for (unsigned i = 1; i <= 32; ++i)
        assert(xt_device_read(d, &packet, 1) == 1 && packet == (BYTE)i);
    assert(xpoll_poll(0) > 0); /* partial drain must retain readiness */
    xpoll_del_event(fd, XPOLL_READABLE);
    push(&s, 32); released(&s, 97);
    assert(xpoll_poll(0) == 0); /* no busy loop while backpressured */
    assert(!xpoll_add_event(fd, XPOLL_READABLE, NULL, NULL, NULL, NULL));
    assert(xpoll_poll(0) > 0); /* backlog wakes immediately after resuming */
    for (unsigned i = 33; i <= 96; ++i)
        assert(xt_device_read(d, &packet, 1) == 1 && packet == (BYTE)i);
    assert(xpoll_poll(0) == 0);
    /* Reader and consumer race over empty/full transitions and the room event. */
    push(&s, 1024);
    for (unsigned i = 97; i < 1121;) {
        assert(xpoll_poll(2000) > 0);
        for (unsigned budget = 0; budget < 32 && i < 1121; ++budget) {
            int n = xt_device_read(d, &packet, 1);
            assert(n >= 0);
            if (!n) break;
            assert(packet == (BYTE)i); ++i;
        }
    }
    assert(xpoll_poll(0) == 0);
    /* Model TCP notification delivery lagging behind a packet already read
     * because another socket woke the loop. The late byte must not spin/fail. */
    EnterCriticalSection(&d->lock);
    d->queue[d->head].n = 1; d->queue[d->head].bytes[0] = 255; d->count = 1;
    LeaveCriticalSection(&d->lock);
    assert(xt_device_read(d, &packet, 1) == 1 && packet == 255);
    EnterCriticalSection(&d->lock); wake_signal(d); LeaveCriticalSection(&d->lock);
    assert(xpoll_poll(1000) > 0);
    assert(xt_device_read(d, &packet, 1) == 0);
    assert(xpoll_poll(0) == 0);
    InterlockedExchange(&s.fail, 1); SetEvent(s.ready);
    assert(xpoll_poll(2000) > 0); /* reader failures wake an idle loop too */
    assert(xt_device_read(d, &packet, 1) == -1);
    xpoll_del_event(fd, XPOLL_ALL);
    xt_device_close(d); CloseHandle(s.ready);
    assert(xpoll_fd_count() == 0); xpoll_uninit(); socket_cleanup();
    puts("PASS Windows TUN wakeup, coalescing, partial drain, backpressure, races and reader failure");
    return 0;
}
