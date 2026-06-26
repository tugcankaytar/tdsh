/*
 * tdsh — minimal TDS client in C
 *
 * Flow (main calls these in order):
 *   1) tcp_connect       — open a TCP connection to the server
 *   2) tds_send_prelogin — send pre-login, drain the response (ENCRYPTION=03 expected)
 *   3) ssl_setup         — set up OpenSSL context + memory BIOs
 *   4) tds_tls_handshake — run the TLS handshake wrapped inside TDS packets
 *   5) Login7            — build and send LOGIN7, confirm LOGINACK
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* ---- Constants ---- */
#define RECV_BUFLEN      16384
#define TLS_BUFLEN       4096

#define TDS_PKT_PRELOGIN 0x12   /* pre-login and TLS-handshake packets are wrapped with this type */
#define TDS_PKT_LOGIN7   0x10   /* Login7 packet type */
#define TDS_STATUS_EOM   0x01   /* End Of Message */
#define TDS_HEADER_LEN   8      /* every TDS packet starts with an 8-byte header */

#define DEBUG 0                 /* 1: diagnostic output on, 0: off */
#define dbg(...) do { if (DEBUG) printf(__VA_ARGS__); } while (0)

/* Pre-login body: example packet from MS-TDS spec 4.1 (47 bytes including header).
 *
 * Structure: 8-byte TDS header, then an option table (5 bytes per entry:
 * 1 type + 2 offset + 2 length, all relative to the start of the payload),
 * a 0xFF terminator, then the option data blocks.
 */
static const unsigned char PRELOGIN_PACKET[] = {
  /* --- TDS header (8 bytes) --- */
  0x12,                   /* Type   = 0x12 (PRELOGIN)                       */
  0x01,                   /* Status = 0x01 (EOM, end of message)           */
  0x00, 0x2F,             /* Length = 0x002F = 47 (whole packet, big-endian)*/
  0x00, 0x00,             /* SPID                                          */
  0x01,                   /* PacketID                                      */
  0x00,                   /* Window                                        */

  /* --- Option table (5 bytes each: type, offset, length) --- */
  0x00, 0x00, 0x1A, 0x00, 0x06,   /* VERSION    @ offset 0x1A, len 6       */
  0x01, 0x00, 0x20, 0x00, 0x01,   /* ENCRYPTION @ offset 0x20, len 1       */
  0x02, 0x00, 0x21, 0x00, 0x01,   /* INSTOPT    @ offset 0x21, len 1       */
  0x03, 0x00, 0x22, 0x00, 0x04,   /* THREADID   @ offset 0x22, len 4       */
  0x04, 0x00, 0x26, 0x00, 0x01,   /* MARS       @ offset 0x26, len 1       */
  0xFF,                           /* terminator — end of option table      */

  /* --- Option data blocks (offsets above point here) --- */
  0x09, 0x00, 0x00, 0x00, 0x00, 0x00,   /* VERSION    data (6 bytes)       */
  0x00,                                 /* ENCRYPTION data (0x00 = ENCRYPT_OFF requested) */
  0x00,                                 /* INSTOPT    data (empty instance) */
  0xB8, 0x0D, 0x00, 0x00,               /* THREADID   data (4 bytes)       */
  0x01                                  /* MARS       data (0x01)          */
};

/* LOGIN7 fixed-length header (36 bytes), per MS-TDS 2.2.6.4.
 * Comes right after the 8-byte TDS packet header. Values taken from the
 * spec's section 4.2 example; only Length is patched at runtime.
*/
static unsigned char LOGIN7_HEADER[] = {
  0x00, 0x00, 0x00, 0x00,   /* Length: total LOGIN7 length (this header +
                               offset table + data), little-endian.
                               Placeholder — overwritten once the packet is built. */

  0x02, 0x00, 0x09, 0x72,   /* TDSVersion: client's TDS protocol version.
                               0x72090002 — SQL Server 2005+ era. Server uses
                               this to decide how to talk to us. Keep as-is. */

  0x00, 0x10, 0x00, 0x00,   /* PacketSize: max TDS packet size we accept,
                               0x00001000 = 4096 bytes, little-endian. */

  0x00, 0x00, 0x00, 0x07,   /* ClientProgVer: our program's version number.
                               Cosmetic — server logs it but doesn't act on it. */

  0x00, 0x01, 0x00, 0x00,   /* ClientPID: our process ID. Cosmetic/diagnostic. */

  0x00, 0x00, 0x00, 0x00,   /* ConnectionID: 0 for a fresh connection
                               (non-zero only when resuming/MARS). */

  0xE0,                     /* OptionFlags1: byte-order, charset, float type,
                               dump/load, USE_DB behaviour. 0xE0 = spec default. */
  0x03,                     /* OptionFlags2: language/ODBC flags.
                               0x03 = INIT_LANG_FATAL | ODBC on. */
  0x00,                     /* TypeFlags: SQL type, OLEDB, read-only intent.
                               0x00 = default (regular SQL login). */
  0x00,                     /* OptionFlags3: extension, change-password, etc.
                               0x00 = none. */

  0x00, 0x00, 0x00, 0x00,   /* ClientTimeZone: minutes offset from UTC.
                               0 — server doesn't reject on this. */

  0x09, 0x04, 0x00, 0x00    /* ClientLCID: locale ID, 0x0409 = en-US,
                               little-endian. Affects collation/language defaults. */
};

/* ============================================================
 *  ASCII -> UTF-16LE
 * ============================================================ */
void ascii_to_utf16le(const char *ascii_str, uint16_t *utf16_str) {
    while (*ascii_str != '\0') {
        *utf16_str = (uint16_t)(*ascii_str);
        ascii_str++;
        utf16_str++;
    }
    *utf16_str = 0x0000; // Null-terminate the UTF-16LE string
}

/* ============================================================
 *  NIBBLE-SWAP
 * ============================================================ */
void apply_transform_utf16le(uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        data[i] = (((data[i] & 0x0F) << 4) | ((data[i] & 0xF0) >> 4)) ^ 0xA5;
    }
}

/* ============================================================
 *  Fill login7 packet
 * ============================================================ */
static void write_field(unsigned char *login7,
                        int *table_pos,        // table cursor (pointer — gets updated)
                        int *data_pos,         // data cursor (pointer — gets updated)
                        const uint16_t *data,  // UTF-16LE data
                        int char_count)        // number of characters
{
  login7[*table_pos + 0] = (*data_pos) & 0xFF;        // offset, low byte first
  login7[*table_pos + 1] = (*data_pos >> 8) & 0xFF;   // offset, high byte
  login7[*table_pos + 2] = char_count & 0xFF;         // length, low byte
  login7[*table_pos + 3] = (char_count >> 8) & 0xFF;  // length, high byte

  if (char_count > 0)
    memcpy(login7 + *data_pos, data, char_count * 2);

  *table_pos += 4;                  // one offset/length pair = 4 bytes
  *data_pos  += char_count * 2;     // each character is 2 bytes (UTF-16LE)
}

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

/* Sends already-encrypted application data: SSL_write then flush wbio raw
 * (no extra TDS header — the TDS header is already inside the encrypted payload). */
static int tds_send_app_data(SSL *ssl, SOCKET s, const unsigned char *data, int len)
{
    int w = SSL_write(ssl, data, len);
    if (w <= 0) return -1;

    unsigned char tlsbuf[TLS_BUFLEN];
    BIO *wbio = SSL_get_wbio(ssl);
    int n = BIO_read(wbio, tlsbuf, sizeof(tlsbuf));
    dbg("BIO_read got %d, wbio still pending: %d\n", n, BIO_pending(wbio));
    if (n <= 0) return -1;

    if (send(s, (const char *)tlsbuf, n, 0) == SOCKET_ERROR) {
        printf("app data send failed: %d\n", WSAGetLastError());
        return -1;
    }
    return n;
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
 * The transport mechanic reused throughout the handshake. */
static int tds_flush_outgoing(SSL *ssl, SOCKET s, unsigned char type)
{
    unsigned char tlsbuf[TLS_BUFLEN];
    BIO *wbio = SSL_get_wbio(ssl);

    int n = BIO_read(wbio, tlsbuf + TDS_HEADER_LEN, sizeof(tlsbuf) - TDS_HEADER_LEN);
    if (n <= 0)
        return 0;

    tds_build_header(tlsbuf, type, n);   // header at the start of the buffer

    if (send(s, (const char *)tlsbuf, TDS_HEADER_LEN + n, 0) == SOCKET_ERROR) {
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

    if (r > TDS_HEADER_LEN) {
        dbg(">>> recv %d bytes, first bytes:", r);
        for (int i = 0; i < (r < 32 ? r : 32); i++)
            dbg(" %02X", recvbuf[i]);
        dbg("\n");
        BIO_write(SSL_get_rbio(ssl), recvbuf + TDS_HEADER_LEN, r - TDS_HEADER_LEN);
    }
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
            printf("HANDSHAKE COMPLETE\n");
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

/* Builds and sends a LOGIN7 packet, then confirms the LOGINACK token.
 * Returns 0 on successful login, -1 otherwise. */
static int Login7(SSL *ssl, SOCKET s, unsigned char *recvbuf, int recvbuflen,
                  const char *username, const char *password, const char *database) {
  uint16_t u16_username[1024];
  uint16_t u16_password[1024];
  uint16_t u16_database[1024];

  ascii_to_utf16le(username, u16_username);
  ascii_to_utf16le(password, u16_password);
  ascii_to_utf16le(database, u16_database);

  int user_bytes = strlen(username) * 2;
  int pass_bytes = strlen(password) * 2;

  dbg("username (UTF-16LE): ");
  for (int i = 0; i < user_bytes; i++)
      dbg("%02X ", ((uint8_t*)u16_username)[i]);
  dbg("\n");

  // obfuscate password (byte level, over the UTF-16LE data)
  apply_transform_utf16le((uint8_t*)u16_password, pass_bytes);

  dbg("password (obfuscated): ");
  for (int i = 0; i < pass_bytes; i++)
      dbg("%02X ", ((uint8_t*)u16_password)[i]);
  dbg("\n");

  unsigned char login7[512];
  memset(login7, 0, sizeof(login7));   // zero first, leave no garbage
  int data_pos = 94;   // first data offset: 36 (fixed header) + 58 (offset table)
  memcpy(login7, LOGIN7_HEADER, sizeof(LOGIN7_HEADER));

  int table_pos = 36;

  // LOGIN7 expects a fixed field order. We fill UserName, Password, Database;
  // the rest are empty (char_count 0). Order must match the spec.
  write_field(login7, &table_pos, &data_pos, NULL, 0);                          // HostName (empty)
  write_field(login7, &table_pos, &data_pos, u16_username, strlen(username));   // UserName
  write_field(login7, &table_pos, &data_pos, u16_password, strlen(password));   // Password
  write_field(login7, &table_pos, &data_pos, NULL, 0);                          // AppName (empty)
  write_field(login7, &table_pos, &data_pos, NULL, 0);                          // ServerName (empty)
  write_field(login7, &table_pos, &data_pos, NULL, 0);  // Unused/Extension
  write_field(login7, &table_pos, &data_pos, NULL, 0);  // CltIntName
  write_field(login7, &table_pos, &data_pos, NULL, 0);  // Language
  write_field(login7, &table_pos, &data_pos, u16_database, strlen(database));  // Database
  memset(login7 + table_pos, 0, 6);  // ClientID (6-byte MAC) — written directly
  table_pos += 6;
  write_field(login7, &table_pos, &data_pos, NULL, 0);  // SSPI
  write_field(login7, &table_pos, &data_pos, NULL, 0);  // AtchDBFile
  write_field(login7, &table_pos, &data_pos, NULL, 0);  // ChangePassword
  memset(login7 + table_pos, 0, 4);  // SSPILong
  table_pos += 4;

  dbg("table_pos=%d (should be 94), data_pos=%d\n", table_pos, data_pos);
  dbg("login7 so far (%d bytes):\n", data_pos);
  for (int i = 0; i < data_pos; i++) {
      dbg("%02X ", login7[i]);
      if ((i + 1) % 16 == 0) dbg("\n");
  }
  dbg("\n");

  // patch the Length field (first 4 bytes) with the total packet length, little-endian
  login7[0] = data_pos & 0xFF;
  login7[1] = (data_pos >> 8) & 0xFF;
  login7[2] = (data_pos >> 16) & 0xFF;
  login7[3] = (data_pos >> 24) & 0xFF;

  // wrap the login7 body in a TDS packet (header goes INSIDE the TLS payload)
  unsigned char tds_login[512];
  tds_build_header(tds_login, TDS_PKT_LOGIN7, data_pos);
  memcpy(tds_login + TDS_HEADER_LEN, login7, data_pos);
  int tds_total = TDS_HEADER_LEN + data_pos;

  dbg("sending login7 (%d bytes incl TDS header)\n", tds_total);
  int sent = tds_send_app_data(ssl, s, tds_login, tds_total);
  dbg("tds_send_app_data returned: %d\n", sent);
  if (sent <= 0) { printf("login7 could not be sent\n"); return -1; }

  DWORD timeout = 15000;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

  int r = tds_feed_incoming(ssl, s, recvbuf, recvbuflen);
  dbg("tds_feed_incoming returned: %d\n", r);
  if (r <= 0) {
      printf("no login response: %d\n", r);
      return -1;
  }

  // response is plaintext TDS (server doesn't encrypt post-login here).
  // parse token stream starting after the 8-byte TDS header.
  unsigned char *tok = recvbuf + TDS_HEADER_LEN;
  int tok_len = r - TDS_HEADER_LEN;

  dbg("login response tokens: ");
  for (int i = 0; i < (tok_len < 32 ? tok_len : 32); i++)
      dbg("%02X ", tok[i]);
  dbg("\n");

  // scan for LOGINACK (0xAD) — its presence means login succeeded
  int login_ok = 0;
  for (int i = 0; i < tok_len; i++) {
      if (tok[i] == 0xAD) { login_ok = 1; break; }
  }
  if (!login_ok) {
      printf("no LOGINACK in response — login failed\n");
      return -1;
  }
  return 0;
}

/* ============================================================
 *  main — orchestrator
 * ============================================================ */

int main(int argc, char *argv[])
{
  if (argc < 6) {
      printf("Usage: %s <host> <port> <username> <password> <database>\n", argv[0]);
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

  s = tcp_connect(argv[1], argv[2]);
  if (s == INVALID_SOCKET)                                  goto cleanup;

  if (tds_send_prelogin(s, recvbuf, RECV_BUFLEN) != 0)      goto cleanup;

  ssl = ssl_setup(&ctx);
  if (!ssl)                                                 goto cleanup;

  if (tds_tls_handshake(ssl, s, recvbuf, RECV_BUFLEN) != 0) goto cleanup;

  printf("TLS channel established\n");

  if (Login7(ssl, s, recvbuf, RECV_BUFLEN, argv[3], argv[4], argv[5]) != 0)
      goto cleanup;

  printf("Login Success\n");
  rc = 0;

cleanup:
  if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }  /* BIOs are freed together with ssl */
  if (ctx) SSL_CTX_free(ctx);
  if (s != INVALID_SOCKET) closesocket(s);
  WSACleanup();
  return rc;
}