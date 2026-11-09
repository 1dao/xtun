#ifndef XDTLS_H
#define XDTLS_H
#include <stddef.h>
#include <stdint.h>

/* Single-owner, nonblocking DTLS 1.2. No socket ownership and no implicit
 * plaintext fallback. send returns length, XDTLS_AGAIN, or XDTLS_ERROR.
 * The caller drives step/read after input and on timer expiry. */
#define XDTLS_AGAIN (-1)
#define XDTLS_ERROR (-2)
#define XDTLS_MAX_RECORD 2048
#define XDTLS_RX_SLOTS 32
typedef struct xDtls xDtls;
typedef struct xDtlsConfig {
    int server;
    const unsigned char *psk; /* exactly 32 random bytes */
    const char *identity;     /* exact expected identity, 1..64 bytes */
    const void *transport_id; /* server: source address+port, stable for session */
    size_t transport_id_len;
    int (*send)(void *, const unsigned char *, size_t);
    void *userdata;
    uint64_t now_ms;          /* monotonic time */
} xDtlsConfig;
xDtls *xdtls_create(const xDtlsConfig *, char error[256]);
void xdtls_destroy(xDtls *);
int xdtls_feed(xDtls *, const void *, size_t); /* copies one complete datagram */
int xdtls_step(xDtls *, uint64_t now_ms); /* 1 ready, 0 pending, -2 fatal */
/* Read returns AGAIN while an application write retry is pending. */
int xdtls_read(xDtls *, void *, size_t);
/* On AGAIN, retry with identical bytes/length before submitting other data. */
int xdtls_write(xDtls *, const void *, size_t);
int xdtls_ready(const xDtls *);
int xdtls_closed(const xDtls *);
int xdtls_last_error(const xDtls *);
const char *xdtls_suite(const xDtls *);
size_t xdtls_max_payload(const xDtls *);
void xdtls_close(xDtls *); /* best effort close_notify, no ownership change */
#endif
