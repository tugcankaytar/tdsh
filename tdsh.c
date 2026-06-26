/*
 * tdsh — minimal TDS client in C
 *
 * Flow (main calls these in order):
 *   1) tcp_connect       — open a TCP connection to the server
 *   2) tds_send_prelogin — send pre-login, drain the response (ENCRYPTION=03 expected)
 *   3) ssl_setup         — set up OpenSSL context + memory BIOs
 *   4) tds_tls_handshake — run the TLS handshake wrapped inside TDS packets
 *   (next: login7, query — over the encrypted channel, via tds_flush/feed helpers)
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* ---- Constants ---- */
#define DEFAULT_PORT     "2604"
#define RECV_BUFLEN      16384
#define TLS_BUFLEN       4096

#define TDS_PKT_PRELOGIN 0x12   /* pre-login and TLS-handshake packets are wrapped with this type */
#define TDS_STATUS_EOM   0x01   /* End Of Message */
#define TDS_HEADER_LEN   8      /* every TDS packet starts with an 8-byte header */

#define DEBUG 1                 /* 1: diagnostic output on, 0: off */
#define dbg(...) do { if (DEBUG) printf(__VA_ARGS__); } while (0)

/* Pre-login body: example packet from MS-TDS spec 4.1 (47 bytes including header). */
static const unsigned char PRELOGIN_PACKET[] = {
    0x12, 0x01, 0x00, 0x2F, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x1A, 0x00, 0x06, 0x01, 0x00, 0x20,
    0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
    0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
    0x01, 0xFF, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0xB8, 0x0D, 0x00, 0x00, 0x01
};

/* ============================================================
 *  TCP layer
 * ============================================================ */

/* Opens a TCP connection to the given host. Returns INVALID_SOCKET on failure. */
static SOCKET tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *result = NULL;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family   = AF_INET;        /* IPv4 only — avoids the IPv6 surprise */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host, port, &hints, &result) != 0) {
        printf("getaddrinfo failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    SOCKET s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        return INVALID_SOCKET;
    }

    if (connect(s, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        printf("connect() failed: %d\n", WSAGetLastError());
        closesocket(s);
        freeaddrinfo(result);
        return INVALID_SOCKET;
    }

    freeaddrinfo(result);
    return s;
}

/* ============================================================
 *  TDS helpers
 * ============================================================ */

/* Builds the 8-byte TDS header. length = TDS_HEADER_LEN + payload, big-endian. */
static void tds_build_header(unsigned char *hdr, unsigned char type, int payload_len)
{
    int total = TDS_HEADER_LEN + payload_len;
    hdr[0] = type;
    hdr[1] = TDS_STATUS_EOM;
    hdr[2] = (total >> 8) & 0xFF;   /* high byte first (big-endian) */
    hdr[3] = total & 0xFF;
    hdr[4] = 0x00; hdr[5] = 0x00;   /* SPID */
    hdr[6] = 0x00;                  /* PacketID */
    hdr[7] = 0x00;                  /* Window */
}

/* Sends the pre-login packet and drains the server's response from the socket.
 * We don't inspect the response (ENCRYPTION=03) here; the goal is just to leave
 * the socket clean for the handshake that follows. */
static int tds_send_prelogin(SOCKET s, unsigned char *recvbuf, int recvbuflen)
{
    int sent = send(s, (const char *)PRELOGIN_PACKET, sizeof(PRELOGIN_PACKET), 0);
    if (sent == SOCKET_ERROR) {
        printf("pre-login send failed: %d\n", WSAGetLastError());
        return -1;
    }
    dbg("pre-login sent: %d bytes\n", sent);

    int got = recv(s, (char *)recvbuf, recvbuflen, 0);
    if (got <= 0) {
        printf("pre-login response not received: %d\n", got);
        return -1;
    }
    dbg("pre-login response received: %d bytes\n", got);
    return 0;
}

/* ============================================================
 *  OpenSSL / TLS layer
 * ============================================================ */

/* Sets up the OpenSSL context, the SSL object and the two memory BIOs.
 * rbio: the one OpenSSL READS from (we write server-sent TLS bytes into it)
 * wbio: the one OpenSSL WRITES to (we read the TLS bytes it wants to send) */
static SSL *ssl_setup(SSL_CTX **out_ctx)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    /* lab environment: accept the self-signed certificate without verification */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);   /* the SSL object now owns the BIOs; no separate free needed */
    SSL_set_connect_state(ssl);

    *out_ctx = ctx;
    return ssl;
}

/* If OpenSSL has data waiting in wbio, wrap it in TDS and write it to the socket.
 * The transport mechanic reused throughout the handshake and beyond. */
static int tds_flush_outgoing(SSL *ssl, SOCKET s, unsigned char type)
{
    unsigned char tlsbuf[TLS_BUFLEN];
    BIO *wbio = SSL_get_wbio(ssl);

    int n = BIO_read(wbio, tlsbuf, sizeof(tlsbuf));
    if (n <= 0)
        return 0;   /* nothing to send */

    unsigned char hdr[TDS_HEADER_LEN];
    tds_build_header(hdr, type, n);

    if (send(s, (const char *)hdr, TDS_HEADER_LEN, 0) == SOCKET_ERROR ||
        send(s, (const char *)tlsbuf, n, 0) == SOCKET_ERROR) {
        printf("TLS payload send failed: %d\n", WSAGetLastError());
        return -1;
    }
    return n;
}

/* Reads one TDS packet from the socket, strips its header and feeds the TLS
 * payload into rbio.
 * NOTE: assumes one TDS packet arrives per recv (holds in the lab).
 * In production: accumulate the full packet based on the length in the header. */
static int tds_feed_incoming(SSL *ssl, SOCKET s, unsigned char *recvbuf, int recvbuflen)
{
    int r = recv(s, (char *)recvbuf, recvbuflen, 0);
    if (r <= 0)
        return r;   /* 0: closed, <0: error */

    dbg(">>> recv %d bytes, first bytes:", r);
    for (int i = 0; i < (r < 12 ? r : 12); i++)
        dbg(" %02X", recvbuf[i]);
    dbg("\n");

    if (r > TDS_HEADER_LEN)
        BIO_write(SSL_get_rbio(ssl), recvbuf + TDS_HEADER_LEN, r - TDS_HEADER_LEN);
    return r;
}

/* Runs the TLS handshake inside TDS envelopes. Returns 0 on success, -1 on error. */
static int tds_tls_handshake(SSL *ssl, SOCKET s, unsigned char *recvbuf, int recvbuflen)
{
    while (1) {
        int ret = SSL_connect(ssl);
        int err = SSL_get_error(ssl, ret);

        /* First: flush everything OpenSSL has produced and is holding (incl. final Finished). */
        if (tds_flush_outgoing(ssl, s, TDS_PKT_PRELOGIN) < 0)
            return -1;

        if (ret == 1) {
            dbg("HANDSHAKE COMPLETE!\n");
            return 0;
        }

        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        if (err == SSL_ERROR_WANT_READ) {
            int r = tds_feed_incoming(ssl, s, recvbuf, recvbuflen);
            if (r <= 0) {
                printf("connection closed during handshake: %d\n", r);
                return -1;
            }
        }
    }
}

/* ============================================================
 *  main — orchestrator
 * ============================================================ */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <host>\n", argv[0]);
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    int rc = 1;                 /* exit code; set to 0 on success */
    SOCKET s     = INVALID_SOCKET;
    SSL_CTX *ctx = NULL;
    SSL *ssl     = NULL;
    unsigned char recvbuf[RECV_BUFLEN];

    s = tcp_connect(argv[1], DEFAULT_PORT);
    if (s == INVALID_SOCKET)                                  goto cleanup;

    if (tds_send_prelogin(s, recvbuf, RECV_BUFLEN) != 0)      goto cleanup;

    ssl = ssl_setup(&ctx);
    if (!ssl)                                                 goto cleanup;

    if (tds_tls_handshake(ssl, s, recvbuf, RECV_BUFLEN) != 0) goto cleanup;

    printf("TLS channel established\n");
    rc = 0;

cleanup:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }  /* BIOs are freed together with ssl */
    if (ctx) SSL_CTX_free(ctx);
    if (s != INVALID_SOCKET) closesocket(s);
    WSACleanup();
    return rc;
}