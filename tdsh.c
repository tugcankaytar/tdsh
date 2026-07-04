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
#define LOGIN7_BUFLEN    512    /* max size of a LOGIN7 packet body we build */
#define U16_FIELD_MAX    1024   /* max chars (incl. null) per UTF-16LE field buffer */

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
/* cap = capacity of utf16_str in uint16_t units (including the null terminator).
 * Never writes past cap; the result is always null-terminated. */
void ascii_to_utf16le(const char *ascii_str, uint16_t *utf16_str, size_t cap) {
    size_t i = 0;
    while (ascii_str[i] != '\0' && i + 1 < cap) {
        utf16_str[i] = (uint16_t)(unsigned char)ascii_str[i];
        i++;
    }
    utf16_str[i] = 0x0000; // Null-terminate the UTF-16LE string
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

/* Decodes and prints a TDS ERROR (0xAA) token so the user sees WHY login failed.
 * p points at the token body (right after the 2-byte length); len is that length.
 * Body layout (MS-TDS 2.2.7.10): Number(4) State(1) Class(1) then MsgText as a
 * US_VARCHAR (2-byte char count + UTF-16LE chars). */
static void print_error_token(const unsigned char *p, int len)
{
    int off = 4 + 1 + 1;                 /* skip Number, State, Class */
    if (off + 2 > len) return;
    int msg_chars = p[off] | (p[off + 1] << 8);
    off += 2;
    if (off + msg_chars * 2 > len)       /* clamp defensively */
        msg_chars = (len - off) / 2;

    printf("server error: ");
    for (int i = 0; i < msg_chars; i++) {
        uint16_t c = p[off + i * 2] | (p[off + i * 2 + 1] << 8);
        putchar(c < 0x80 ? (char)c : '?');   /* ASCII-print; non-ASCII -> '?' */
    }
    printf("\n");
}

/* Walks the TDS token stream of a login response and reports success/failure.
 * Returns 0 if a LOGINACK (0xAD) token is present, -1 otherwise.
 *
 * Token length classes (MS-TDS 2.2.3): variable-length tokens — including
 * LOGINACK, ERROR, INFO, ENVCHANGE — are identified by (type & 0x30) == 0x20
 * and carry a 2-byte (USHORT) length prefix. DONE/DONEPROC/DONEINPROC are
 * fixed 12-byte bodies under TDS 7.2 (Status 2 + CurCmd 2 + RowCount 8).
 * Anything else we can't safely skip, so we stop. */
static int parse_login_response(const unsigned char *tok, int tok_len)
{
    int i = 0, login_ok = 0;

    while (i < tok_len) {
        unsigned char type = tok[i++];

        if ((type & 0x30) == 0x20) {             /* variable-length token */
            if (i + 2 > tok_len) break;
            int len = tok[i] | (tok[i + 1] << 8);
            i += 2;
            if (len > tok_len - i)               /* clamp to what we actually have */
                len = tok_len - i;

            if (type == 0xAD)        login_ok = 1;              /* LOGINACK */
            else if (type == 0xAA)   print_error_token(tok + i, len); /* ERROR */

            i += len;
        } else if (type == 0xFD || type == 0xFE || type == 0xFF) {
            i += 12;                             /* DONE / DONEPROC / DONEINPROC */
        } else {
            dbg("unknown token 0x%02X at offset %d, stopping parse\n", type, i - 1);
            break;
        }
    }

    if (!login_ok)
        printf("no LOGINACK in response — login failed\n");
    return login_ok ? 0 : -1;
}

/* Builds and sends a LOGIN7 packet, then confirms the LOGINACK token.
 * Returns 0 on successful login, -1 otherwise. */
static int Login7(SSL *ssl, SOCKET s, unsigned char *recvbuf, int recvbuflen,
                  const char *username, const char *password, const char *database) {
  size_t ulen = strlen(username);
  size_t plen = strlen(password);
  size_t dlen = strlen(database);

  /* Bounds check 1: each field must fit its UTF-16LE buffer (incl. null). */
  if (ulen >= U16_FIELD_MAX || plen >= U16_FIELD_MAX || dlen >= U16_FIELD_MAX) {
      printf("username/password/database too long (max %d chars each)\n",
             U16_FIELD_MAX - 1);
      return -1;
  }
  /* Bounds check 2: header (36) + offset table (58) + field data must fit login7[].
   * data starts at offset 94; each char is 2 bytes. */
  if (94 + (ulen + plen + dlen) * 2 > LOGIN7_BUFLEN) {
      printf("credentials too large for LOGIN7 buffer (%d bytes)\n", LOGIN7_BUFLEN);
      return -1;
  }

  uint16_t u16_username[U16_FIELD_MAX];
  uint16_t u16_password[U16_FIELD_MAX];
  uint16_t u16_database[U16_FIELD_MAX];

  ascii_to_utf16le(username, u16_username, U16_FIELD_MAX);
  ascii_to_utf16le(password, u16_password, U16_FIELD_MAX);
  ascii_to_utf16le(database, u16_database, U16_FIELD_MAX);

  int user_bytes = (int)(ulen * 2);
  int pass_bytes = (int)(plen * 2);

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

  unsigned char login7[LOGIN7_BUFLEN];
  memset(login7, 0, sizeof(login7));   // zero first, leave no garbage
  int data_pos = 94;   // first data offset: 36 (fixed header) + 58 (offset table)
  memcpy(login7, LOGIN7_HEADER, sizeof(LOGIN7_HEADER));

  int table_pos = 36;

  // LOGIN7 expects a fixed field order. We fill UserName, Password, Database;
  // the rest are empty (char_count 0). Order must match the spec.
  write_field(login7, &table_pos, &data_pos, NULL, 0);                        // HostName (empty)
  write_field(login7, &table_pos, &data_pos, u16_username, (int)ulen);        // UserName
  write_field(login7, &table_pos, &data_pos, u16_password, (int)plen);        // Password
  write_field(login7, &table_pos, &data_pos, NULL, 0);                        // AppName (empty)
  write_field(login7, &table_pos, &data_pos, NULL, 0);                        // ServerName (empty)
  write_field(login7, &table_pos, &data_pos, NULL, 0);  // Unused/Extension
  write_field(login7, &table_pos, &data_pos, NULL, 0);  // CltIntName
  write_field(login7, &table_pos, &data_pos, NULL, 0);  // Language
  write_field(login7, &table_pos, &data_pos, u16_database, (int)dlen);        // Database
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
  unsigned char tds_login[TDS_HEADER_LEN + LOGIN7_BUFLEN];
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

  // walk the token stream; confirms LOGINACK and surfaces any ERROR message
  return parse_login_response(tok, tok_len);
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