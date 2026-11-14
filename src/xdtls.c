#include "xdtls.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"

struct xDtls {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ssl_cookie_ctx cookie;
    mbedtls_ctr_drbg_context rng;
    mbedtls_entropy_context entropy;
    int (*send)(void *, const unsigned char *, size_t);
    void *userdata;
    unsigned char transport[128];
    size_t transport_len;
    unsigned char psk[32];
    char identity[65];
    struct { size_t len; unsigned char bytes[XDTLS_MAX_RECORD]; } rx[XDTLS_RX_SLOTS];
    unsigned head, count;
    uint64_t now, timer_start;
    uint32_t timer_intermediate, timer_final;
    int server, ready, closed, error, write_pending;
};

static int fail(xDtls *d, int rc) { d->error = rc; d->closed = 1; return XDTLS_ERROR; }
static int net_send(void *p, const unsigned char *data, size_t n) {
    xDtls *d = p;
    int rc = d->send(d->userdata, data, n);
    if (rc == XDTLS_AGAIN) return MBEDTLS_ERR_SSL_WANT_WRITE;
    return rc == (int)n ? rc : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static int net_recv(void *p, unsigned char *data, size_t cap) {
    xDtls *d = p;
    if (!d->count) return MBEDTLS_ERR_SSL_WANT_READ;
    size_t n = d->rx[d->head].len;
    if (n > cap) return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    memcpy(data, d->rx[d->head].bytes, n);
    d->head = (d->head + 1) % XDTLS_RX_SLOTS;
    --d->count;
    return (int)n;
}
static void timer_set(void *p, uint32_t middle, uint32_t final) {
    xDtls *d = p;
    d->timer_start = d->now;
    d->timer_intermediate = middle;
    d->timer_final = final;
}
static int timer_get(void *p) {
    xDtls *d = p;
    if (!d->timer_final) return -1;
    uint64_t elapsed = d->now - d->timer_start;
    return elapsed >= d->timer_final ? 2 : elapsed >= d->timer_intermediate ? 1 : 0;
}
static int lookup_psk(void *p, mbedtls_ssl_context *ssl,
                      const unsigned char *id, size_t n) {
    xDtls *d = p;
    size_t expected = strlen(d->identity);
    if (n != expected || memcmp(id, d->identity, n)) return -1;
    return mbedtls_ssl_set_hs_psk(ssl, d->psk, sizeof(d->psk));
}
static int bind_transport(xDtls *d) {
    if (!d->server) return 0;
    return mbedtls_ssl_set_client_transport_id(&d->ssl, d->transport, d->transport_len);
}
xDtls *xdtls_create(const xDtlsConfig *cfg, char error[256]) {
    static const int suites[] = { MBEDTLS_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, 0 };
    static const uint16_t groups[] = { MBEDTLS_SSL_IANA_TLS_GROUP_X25519, 0 };
    xDtls *d;
    int rc;
    if (error) error[0] = 0;
    if (!cfg || !cfg->psk || !cfg->identity || !cfg->send ||
        !*cfg->identity || strlen(cfg->identity) > 64 ||
        (cfg->server && (!cfg->transport_id || !cfg->transport_id_len || cfg->transport_id_len > 128))) {
        if (error) snprintf(error, 256, "invalid DTLS configuration");
        return NULL;
    }
    d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    mbedtls_ssl_init(&d->ssl); mbedtls_ssl_config_init(&d->conf);
    mbedtls_ssl_cookie_init(&d->cookie); mbedtls_ctr_drbg_init(&d->rng);
    mbedtls_entropy_init(&d->entropy);
    d->server = !!cfg->server; d->send = cfg->send; d->userdata = cfg->userdata;
    d->now = cfg->now_ms;
    memcpy(d->psk, cfg->psk, 32); strcpy(d->identity, cfg->identity);
    if (d->server) {
        memcpy(d->transport, cfg->transport_id, cfg->transport_id_len);
        d->transport_len = cfg->transport_id_len;
    }
    if ((rc = psa_crypto_init()) != PSA_SUCCESS) goto bad;
    if ((rc = mbedtls_ctr_drbg_seed(&d->rng, mbedtls_entropy_func, &d->entropy,
                                    (const unsigned char *)"xdtls-v1", 8))) goto bad;
    if ((rc = mbedtls_ssl_config_defaults(&d->conf,
            d->server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT))) goto bad;
    mbedtls_ssl_conf_min_tls_version(&d->conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&d->conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_ciphersuites(&d->conf, suites);
    mbedtls_ssl_conf_groups(&d->conf, groups);
    mbedtls_ssl_conf_rng(&d->conf, mbedtls_ctr_drbg_random, &d->rng);
    mbedtls_ssl_conf_dtls_anti_replay(&d->conf, MBEDTLS_SSL_ANTI_REPLAY_ENABLED);
    mbedtls_ssl_conf_handshake_timeout(&d->conf, 500, 4000);
    mbedtls_ssl_conf_session_tickets(&d->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
    mbedtls_ssl_conf_renegotiation(&d->conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
    if (d->server) {
        mbedtls_ssl_conf_psk_cb(&d->conf, lookup_psk, d);
        if ((rc = mbedtls_ssl_cookie_setup(&d->cookie, mbedtls_ctr_drbg_random, &d->rng))) goto bad;
        mbedtls_ssl_conf_dtls_cookies(&d->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &d->cookie);
    } else if ((rc = mbedtls_ssl_conf_psk(&d->conf, d->psk, 32,
                   (const unsigned char *)d->identity, strlen(d->identity)))) goto bad;
    if ((rc = mbedtls_ssl_setup(&d->ssl, &d->conf))) goto bad;
    mbedtls_ssl_set_mtu(&d->ssl, 1400);
    mbedtls_ssl_set_bio(&d->ssl, d, net_send, net_recv, NULL);
    mbedtls_ssl_set_timer_cb(&d->ssl, d, timer_set, timer_get);
    if ((rc = bind_transport(d))) goto bad;
    return d;
bad:
    if (error) mbedtls_strerror(rc, error, 256);
    xdtls_destroy(d);
    return NULL;
}
void xdtls_destroy(xDtls *d) {
    if (!d) return;
    mbedtls_ssl_free(&d->ssl); mbedtls_ssl_config_free(&d->conf);
    mbedtls_ssl_cookie_free(&d->cookie); mbedtls_ctr_drbg_free(&d->rng);
    mbedtls_entropy_free(&d->entropy);
    mbedtls_platform_zeroize(d, sizeof(*d)); free(d);
}
int xdtls_feed(xDtls *d, const void *bytes, size_t n) {
    if (!d || d->closed || !bytes || !n || n > XDTLS_MAX_RECORD || d->count == XDTLS_RX_SLOTS)
        return XDTLS_ERROR;
    unsigned tail = (d->head + d->count) % XDTLS_RX_SLOTS;
    memcpy(d->rx[tail].bytes, bytes, n); d->rx[tail].len = n; ++d->count;
    return 0;
}
int xdtls_step(xDtls *d, uint64_t now) {
    if (!d || d->closed) return XDTLS_ERROR;
    if (now < d->now) return fail(d, MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    d->now = now;
    if (d->ready) return 1;
    int rc = mbedtls_ssl_handshake(&d->ssl);
    if (!rc) { d->ready = 1; return 1; }
    if (rc == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED && d->server) {
        if ((rc = mbedtls_ssl_session_reset(&d->ssl)) || (rc = bind_transport(d))) return fail(d, rc);
        return 0;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    return fail(d, rc);
}
int xdtls_read(xDtls *d, void *out, size_t n) {
    if (!d || !d->ready || d->closed) return XDTLS_ERROR;
    /* DTLS ssl_read flushes output. Doing so between WANT_WRITE and the
     * matching write retry would lose ssl_write's pending-record marker and
     * encrypt/send the same application datagram again with a new sequence. */
    if (d->write_pending) return XDTLS_AGAIN;
    int rc = mbedtls_ssl_read(&d->ssl, out, n);
    if (rc > 0) return rc;
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return XDTLS_AGAIN;
    return fail(d, rc);
}
int xdtls_write(xDtls *d, const void *bytes, size_t n) {
    if (!d || !d->ready || d->closed || !bytes || !n || n > xdtls_max_payload(d)) return XDTLS_ERROR;
    int rc = mbedtls_ssl_write(&d->ssl, bytes, n);
    d->write_pending = rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE;
    if (d->write_pending) return XDTLS_AGAIN;
    return rc > 0 ? rc : fail(d, rc);
}
int xdtls_ready(const xDtls *d) { return d && d->ready && !d->closed; }
unsigned xdtls_input_space(const xDtls *d) { return d && !d->closed ? XDTLS_RX_SLOTS - d->count : 0; }
int xdtls_write_pending(const xDtls *d) { return d && d->write_pending; }
int xdtls_closed(const xDtls *d) { return !d || d->closed; }
int xdtls_last_error(const xDtls *d) { return d ? d->error : 0; }
const char *xdtls_suite(const xDtls *d) { return xdtls_ready(d) ? mbedtls_ssl_get_ciphersuite(&d->ssl) : "none"; }
size_t xdtls_max_payload(const xDtls *d) {
    if (!xdtls_ready(d)) return 0;
    int n = mbedtls_ssl_get_max_out_record_payload(&d->ssl);
    return n > 0 ? (size_t)n : 0;
}
void xdtls_close(xDtls *d) {
    if (!d || d->closed) return;
    if (d->ready) (void)mbedtls_ssl_close_notify(&d->ssl);
    d->closed = 1;
}
