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
#include <stdlib.h>
#include <string.h>
#include <conio.h>    /* _getch — read password keystrokes without echoing them */

#include <openssl/ssl.h>
#include <openssl/err.h>

/* ---- Constants ---- */
#define RECV_BUFLEN      16384
#define TLS_BUFLEN       4096
#define LOGIN7_BUFLEN    512    /* max size of a LOGIN7 packet body we build */
#define U16_FIELD_MAX    1024   /* max chars (incl. null) per UTF-16LE field buffer */

#define TDS_PKT_PRELOGIN 0x12   /* pre-login and TLS-handshake packets are wrapped with this type */
#define TDS_PKT_LOGIN7   0x10   /* Login7 packet type */
#define TDS_PKT_SQLBATCH 0x01   /* SQL batch (query) packet type */
#define TDS_STATUS_EOM   0x01   /* End Of Message (status byte bit 0) */
#define TDS_HEADER_LEN   8      /* every TDS packet starts with an 8-byte header */
#define TDS_PKT_SIZE     4096   /* negotiated packet size (matches LOGIN7 PacketSize) */

/* Pre-login ENCRYPTION option values (MS-TDS 2.2.6.5) */
#define TDS_ENCRYPT_OFF     0x00   /* encrypt login only */
#define TDS_ENCRYPT_ON      0x01   /* encrypt the whole session */
#define TDS_ENCRYPT_NOT_SUP 0x02   /* no encryption */
#define TDS_ENCRYPT_REQ     0x03   /* encryption required (whole session) */

/* 1 => the whole session is TLS-encrypted after the handshake, so query
 * traffic must go through SSL_read/SSL_write. Set from the pre-login response. */
static int g_encrypt = 0;

/* 1 => force expanded (one field per line) result display; 0 => auto (expanded
 * only when a table is too wide for the terminal). Toggled with \x in the REPL. */
static int g_expanded = 0;

/* 1 => ANSI escape (virtual terminal) processing is enabled on the console, so
 * \clear can wipe the scrollback with ESC[3J instead of just the visible area. */
static int g_vt = 0;

/* 1 => page long result sets one screen at a time (like `less`/psql's pager);
 * 0 => dump everything at once. Toggled with \pager in the REPL. */
static int g_pager = 1;

/* ANSI SGR codes for the connection form and result tables. They expand to ""
 * when VT processing is off (older console), so everything still reads cleanly
 * without colours. */
#define CLR_RESET  (g_vt ? "\x1b[0m"  : "")
#define CLR_BOLD   (g_vt ? "\x1b[1m"  : "")
#define CLR_DIM    (g_vt ? "\x1b[2m"  : "")
#define CLR_CYAN   (g_vt ? "\x1b[36m" : "")
#define CLR_GREEN  (g_vt ? "\x1b[32m" : "")
#define CLR_RED    (g_vt ? "\x1b[31m" : "")
#define CLR_YELLOW (g_vt ? "\x1b[33m" : "")
#define CLR_BLUE   (g_vt ? "\x1b[34m" : "")

/* Box-drawing glyphs for result tables. Unicode line-drawing on a modern
 * console (the output CP is UTF-8), ASCII fallback when VT is unavailable so
 * the grid still reads on legacy consoles. Indices: horizontal, vertical, then
 * the corners/junctions top-left..bottom-right. */
typedef struct {
    const char *h, *v;
    const char *tl, *tm, *tr;   /* top    row: ┌ ┬ ┐ */
    const char *ml, *mm, *mr;   /* middle sep: ├ ┼ ┤ */
    const char *bl, *bm, *br;   /* bottom row: └ ┴ ┘ */
} BoxChars;

static BoxChars box_chars(void)
{
    if (g_vt) {
        BoxChars b = { "\xe2\x94\x80", "\xe2\x94\x82",
                       "\xe2\x94\x8c", "\xe2\x94\xac", "\xe2\x94\x90",
                       "\xe2\x94\x9c", "\xe2\x94\xbc", "\xe2\x94\xa4",
                       "\xe2\x94\x94", "\xe2\x94\xb4", "\xe2\x94\x98" };
        return b;
    }
    BoxChars b = { "-", "|", "+", "+", "+", "+", "+", "+", "+", "+", "+" };
    return b;
}

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

/* forward declarations: defined further below, but needed earlier —
 * tds_read_message by Login7, utf8_from_utf16le by print_error_token. */
static unsigned char *tds_read_message(SSL *ssl, SOCKET s, int enc, int *outlen);
static void utf8_from_utf16le(const unsigned char *v, int nbytes, char *out, int outcap);

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
  0x00                                  /* MARS       data (0x00 = OFF).
                                           MARS ON requires wrapping every
                                           post-login packet in an SMP header,
                                           which this client does not implement,
                                           so we must NOT negotiate MARS.      */
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

/* Sends the pre-login packet and reads the server's response, parsing the
 * ENCRYPTION option to decide whether the whole session will be encrypted
 * (sets g_encrypt). The response is otherwise not needed by the handshake. */
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

    /* Walk the option table (5 bytes/entry, offsets relative to the payload)
     * to find ENCRYPTION (type 0x01) and read the negotiated mode. */
    int base = TDS_HEADER_LEN;
    for (int p = base; p + 5 <= got && recvbuf[p] != 0xFF; p += 5) {
        if (recvbuf[p] == 0x01) {                       /* ENCRYPTION option */
            int off = (recvbuf[p + 1] << 8) | recvbuf[p + 2];
            int dpos = base + off;
            if (dpos < got) {
                int enc = recvbuf[dpos];
                g_encrypt = (enc == TDS_ENCRYPT_ON || enc == TDS_ENCRYPT_REQ);
                dbg("pre-login ENCRYPTION = 0x%02X\n", enc);
            }
            break;
        }
    }
    printf("session encryption: %s\n", g_encrypt ? "ON (whole session via TLS)"
                                                 : "OFF (login only)");
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

    char msg[2048];
    utf8_from_utf16le(p + off, msg_chars * 2, msg, sizeof msg);
    printf("%s%serror:%s %s%s%s\n",
           CLR_BOLD, CLR_RED, CLR_RESET, CLR_RED, msg, CLR_RESET);
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
static int Login7(SSL *ssl, SOCKET s,
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

  // Read the login response through the transport the session uses: TLS when
  // encryption is ON, plaintext when the server encrypts the login only.
  // tds_read_message strips packet headers and returns the token stream.
  int tok_len = 0;
  unsigned char *tok = tds_read_message(ssl, s, g_encrypt, &tok_len);
  if (!tok) { printf("no login response\n"); return -1; }

  dbg("login response token stream (%d bytes)\n", tok_len);

  // walk the token stream; confirms LOGINACK and surfaces any ERROR message
  int lrc = parse_login_response(tok, tok_len);
  free(tok);
  return lrc;
}

/* ============================================================
 *  Query execution  (SQL batch -> result token stream -> table)
 *
 *  Encryption note: the transport depends on what pre-login negotiated.
 *  With ENCRYPT_ON/REQ (g_encrypt=1) the whole session is TLS, so batches and
 *  responses go through SSL_write/SSL_read. With ENCRYPT_OFF only the login is
 *  encrypted and query traffic is plaintext TDS over the raw socket. The helpers
 *  below take an `enc` flag and pick the transport accordingly.
 * ============================================================ */

/* --- little-endian helpers --- */
static void put_u32le(unsigned char *p, uint32_t v)
{
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
static unsigned long long read_uint_le(const unsigned char *v, int n)
{
    unsigned long long u = 0;
    for (int k = 0; k < n; k++) u |= (unsigned long long)v[k] << (8 * k);
    return u;
}
static long long read_int_le(const unsigned char *v, int n)   /* signed, sign-extended */
{
    unsigned long long u = read_uint_le(v, n);
    if (n < 8 && (u & (1ULL << (8 * n - 1))))
        u |= ~((1ULL << (8 * n)) - 1);
    return (long long)u;
}
static unsigned long long pow10_ull(int e)
{
    unsigned long long r = 1;
    while (e-- > 0) r *= 10;
    return r;
}

/* --- socket send/recv that transfer exactly n bytes (TCP may fragment) --- */
static int send_all(SOCKET s, const unsigned char *buf, int n)
{
    int off = 0;
    while (off < n) {
        int w = send(s, (const char *)buf + off, n - off, 0);
        if (w == SOCKET_ERROR) return -1;
        off += w;
    }
    return off;
}
static int recv_all(SOCKET s, unsigned char *buf, int n)
{
    int off = 0;
    while (off < n) {
        int r = recv(s, (char *)buf + off, n - off, 0);
        if (r <= 0) return r;   /* 0 closed, <0 error */
        off += r;
    }
    return off;
}

/* --- same, but through the TLS channel (used when g_encrypt is set) --- */
static int ssl_send_all(SSL *ssl, SOCKET s, const unsigned char *buf, int n)
{
    if (SSL_write(ssl, buf, n) <= 0) return -1;   /* buffers into wbio (memory BIO) */

    unsigned char tmp[TLS_BUFLEN];
    BIO *wbio = SSL_get_wbio(ssl);
    int m;
    while ((m = BIO_read(wbio, tmp, sizeof(tmp))) > 0)   /* drain the TLS records */
        if (send_all(s, tmp, m) < 0) return -1;
    return n;
}
static int ssl_read_all(SSL *ssl, SOCKET s, unsigned char *buf, int n)
{
    int off = 0;
    while (off < n) {
        int r = SSL_read(ssl, buf + off, n - off);
        if (r > 0) { off += r; continue; }
        if (SSL_get_error(ssl, r) == SSL_ERROR_WANT_READ) {
            unsigned char tmp[TLS_BUFLEN];               /* feed more ciphertext in */
            int g = recv(s, (char *)tmp, sizeof(tmp), 0);
            if (g <= 0) return -1;
            BIO_write(SSL_get_rbio(ssl), tmp, g);
        } else {
            return -1;
        }
    }
    return off;
}

/* Transport-agnostic exact reads: TLS when enc, raw socket otherwise. */
static int xfer_recv_all(SSL *ssl, SOCKET s, int enc, unsigned char *buf, int n)
{
    return enc ? ssl_read_all(ssl, s, buf, n) : recv_all(s, buf, n);
}

/* Frames a message into TDS packets (≤ TDS_PKT_SIZE, EOM only on the last) and
 * sends it — over TLS when enc is set, otherwise as raw plaintext. */
static int tds_send_message(SSL *ssl, SOCKET s, int enc, unsigned char type,
                            const unsigned char *data, int datalen)
{
    int cap = TDS_PKT_SIZE - TDS_HEADER_LEN;        /* payload capacity per packet */
    int npkts = datalen > 0 ? (datalen + cap - 1) / cap : 1;
    int framed_len = datalen + npkts * TDS_HEADER_LEN;
    unsigned char *framed = malloc(framed_len);
    if (!framed) return -1;

    int off = 0, o = 0;
    unsigned char pid = 1;
    do {
        int chunk = datalen - off;
        if (chunk > cap) chunk = cap;
        int last = (off + chunk >= datalen);
        int total = TDS_HEADER_LEN + chunk;

        framed[o + 0] = type;
        framed[o + 1] = last ? TDS_STATUS_EOM : 0x00;
        framed[o + 2] = (total >> 8) & 0xFF;
        framed[o + 3] = total & 0xFF;
        framed[o + 4] = 0x00; framed[o + 5] = 0x00;   /* SPID */
        framed[o + 6] = pid++;                        /* PacketID */
        framed[o + 7] = 0x00;                         /* Window */
        memcpy(framed + o + TDS_HEADER_LEN, data + off, chunk);

        o += total;
        off += chunk;
    } while (off < datalen);

    int rc = enc ? ssl_send_all(ssl, s, framed, o)
                 : (send_all(s, framed, o) < 0 ? -1 : o);
    free(framed);
    return rc < 0 ? -1 : 0;
}

/* Reads a complete TDS message: keeps reading packets (reassembling across
 * transport boundaries) until one arrives with the EOM bit set, concatenating
 * their payloads. Returns a malloc'd token buffer (caller frees) and sets
 * *outlen, or NULL on error. Uses TLS when enc is set. */
static unsigned char *tds_read_message(SSL *ssl, SOCKET s, int enc, int *outlen)
{
    int cap = 65536, total = 0;
    unsigned char *buf = malloc(cap);
    unsigned char hdr[TDS_HEADER_LEN];
    if (!buf) return NULL;

    for (;;) {
        if (xfer_recv_all(ssl, s, enc, hdr, TDS_HEADER_LEN) <= 0) { free(buf); return NULL; }

        int pkt_len = (hdr[2] << 8) | hdr[3];   /* whole packet, big-endian */
        int payload = pkt_len - TDS_HEADER_LEN;
        if (payload < 0) { free(buf); return NULL; }

        if (total + payload > cap) {
            while (total + payload > cap) cap *= 2;
            unsigned char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        if (payload > 0) {
            if (xfer_recv_all(ssl, s, enc, buf + total, payload) <= 0) { free(buf); return NULL; }
            total += payload;
        }
        if (hdr[1] & TDS_STATUS_EOM) break;   /* last packet of the message */
    }

    *outlen = total;
    return buf;
}

/* ============================================================
 *  Result-set token stream: metadata, values, table rendering
 * ============================================================ */

#define MAX_COLS   1024
#define CELL_MAX   4096   /* max formatted cell / assembled PLP value */
#define MAX_ROWS   100000 /* safety cap on buffered rows per result set */

/* how a value's length is encoded in a ROW */
enum len_cat { LC_FIXED, LC_BYTE, LC_USHORT, LC_LONG, LC_PLP, LC_UNSUPPORTED };

typedef struct {
    char     name[128];
    uint8_t  type;        /* TDS type token */
    int      len_cat;
    int      fixed_size;  /* for LC_FIXED */
    int      max_len;     /* declared max length (bytes) */
    uint8_t  precision;   /* DECIMAL/NUMERIC */
    uint8_t  scale;       /* DECIMAL/NUMERIC, TIME/DATETIME2/DATETIMEOFFSET */
    int      is_unicode;  /* n(var)char / ntext */
    int      is_binary;   /* (var)binary / image */
} Column;

typedef struct {
    int      ncols;
    Column   cols[MAX_COLS];
    char  ***rows;        /* rows[r][c] = malloc'd cell string */
    int      nrows, cap;
    int      truncated;   /* hit MAX_ROWS */
} Table;

/* Converts a little-endian magnitude to a decimal digit string (MSB first). */
static void mag_to_decimal(const unsigned char *mag, int n, char *out, int outcap)
{
    unsigned char tmp[16];
    if (n > 16) n = 16;
    memcpy(tmp, mag, n);

    char rev[80];
    int c = 0;
    for (;;) {
        int nonzero = 0;
        for (int k = 0; k < n; k++) if (tmp[k]) { nonzero = 1; break; }
        if (!nonzero) break;

        int rem = 0;
        for (int k = n - 1; k >= 0; k--) {
            int cur = (rem << 8) | tmp[k];
            tmp[k] = (unsigned char)(cur / 10);
            rem = cur % 10;
        }
        if (c < (int)sizeof(rev)) rev[c++] = (char)('0' + rem);
    }
    if (c == 0) rev[c++] = '0';

    int j = 0;
    for (int k = c - 1; k >= 0 && j < outcap - 1; k--) out[j++] = rev[k];
    out[j] = '\0';
}

/* days since 1970-01-01 -> civil Y/M/D (Howard Hinnant's algorithm) */
static void civil_from_days(long long z, int *y, int *m, int *d)
{
    z += 719468;
    long long era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int yy = (int)yoe + (int)(era * 400);
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    unsigned dd = doy - (153 * mp + 2) / 5 + 1;
    unsigned mm = mp < 10 ? mp + 3 : mp - 9;
    *y = yy + (mm <= 2);
    *m = (int)mm;
    *d = (int)dd;
}

/* Formats a time-of-day given as a count of 10^-scale seconds since midnight. */
static void fmt_time(unsigned long long value, int scale, char *out, int outcap)
{
    if (scale < 0) scale = 0;
    if (scale > 7) scale = 7;                 /* T-SQL fractional-second scale is 0..7 */
    unsigned long long denom = pow10_ull(scale);
    unsigned long long secs = value / denom;
    unsigned long long frac = value % denom;
    int hh = (int)(secs / 3600), mm = (int)((secs % 3600) / 60), ss = (int)(secs % 60);
    if (scale > 0)
        snprintf(out, outcap, "%02d:%02d:%02d.%0*llu", hh, mm, ss, scale, frac);
    else
        snprintf(out, outcap, "%02d:%02d:%02d", hh, mm, ss);
}

/* ---- UTF-8 output helpers (the console is switched to CP_UTF8 in main) ---- */

/* Encode one Unicode code point as UTF-8 at out[j..]; returns the new j. */
static int utf8_put(char *out, int j, int outcap, unsigned int cp)
{
    if (cp < 0x80) {
        if (j + 1 < outcap) out[j++] = (char)cp;
    } else if (cp < 0x800) {
        if (j + 2 < outcap) { out[j++] = (char)(0xC0 | (cp >> 6)); out[j++] = (char)(0x80 | (cp & 0x3F)); }
    } else if (cp < 0x10000) {
        if (j + 3 < outcap) { out[j++] = (char)(0xE0 | (cp >> 12)); out[j++] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[j++] = (char)(0x80 | (cp & 0x3F)); }
    } else {
        if (j + 4 < outcap) { out[j++] = (char)(0xF0 | (cp >> 18)); out[j++] = (char)(0x80 | ((cp >> 12) & 0x3F)); out[j++] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[j++] = (char)(0x80 | (cp & 0x3F)); }
    }
    return j;
}

/* UTF-16LE bytes -> UTF-8 string (handles surrogate pairs). */
static void utf8_from_utf16le(const unsigned char *v, int nbytes, char *out, int outcap)
{
    int j = 0;
    for (int i = 0; i + 1 < nbytes; i += 2) {
        unsigned int cp = v[i] | (v[i + 1] << 8);
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 3 < nbytes) {      /* high surrogate */
            unsigned int lo = v[i + 2] | (v[i + 3] << 8);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            }
        }
        j = utf8_put(out, j, outcap, cp);
    }
    out[j] = '\0';
}

/* Single-byte (collation codepage) bytes -> UTF-8, via the system ANSI codepage
 * (Windows-1254 on a Turkish system). Best-effort for legacy varchar/char. */
static void utf8_from_ansi(const unsigned char *v, int n, char *out, int outcap)
{
    wchar_t wbuf[CELL_MAX];
    int wn = MultiByteToWideChar(CP_ACP, 0, (const char *)v, n, wbuf, CELL_MAX);
    if (wn <= 0) {                                   /* fallback: copy raw bytes */
        int cpy = n < outcap - 1 ? n : outcap - 1;
        memcpy(out, v, cpy); out[cpy] = '\0'; return;
    }
    int bn = WideCharToMultiByte(CP_UTF8, 0, wbuf, wn, out, outcap - 1, NULL, NULL);
    if (bn < 0) bn = 0;
    out[bn] = '\0';
}

/* Formats one non-null value (raw bytes v[0..n)) into a text cell. */
static void format_cell(const Column *c, const unsigned char *v, int n, char *out, int outcap)
{
    switch (c->type) {
    /* ---- integers ---- */
    case 0x30:                                   /* tinyint (unsigned) */
        snprintf(out, outcap, "%u", (unsigned)v[0]); return;
    case 0x34: snprintf(out, outcap, "%lld", read_int_le(v, 2)); return; /* smallint */
    case 0x38: snprintf(out, outcap, "%lld", read_int_le(v, 4)); return; /* int */
    case 0x7F: snprintf(out, outcap, "%lld", read_int_le(v, 8)); return; /* bigint */
    case 0x26:                                   /* INTN */
        if (n == 1) snprintf(out, outcap, "%u", (unsigned)v[0]);
        else        snprintf(out, outcap, "%lld", read_int_le(v, n));
        return;

    /* ---- bit ---- */
    case 0x32: case 0x68:
        snprintf(out, outcap, "%d", v[0] ? 1 : 0); return;

    /* ---- floating point ---- */
    case 0x3B: { float f;  memcpy(&f, v, 4); snprintf(out, outcap, "%g", (double)f); return; }
    case 0x3E: { double d; memcpy(&d, v, 8); snprintf(out, outcap, "%g", d);        return; }
    case 0x6D:                                   /* FLTN */
        if (n == 4) { float f; memcpy(&f, v, 4); snprintf(out, outcap, "%g", (double)f); }
        else        { double d; memcpy(&d, v, 8); snprintf(out, outcap, "%g", d); }
        return;

    /* ---- money (scaled by 10000, high/low 32-bit words swapped) ---- */
    case 0x3C: case 0x7A: case 0x6E: {
        long long val;
        if (n == 4) val = read_int_le(v, 4);
        else { long long hi = read_int_le(v, 4); unsigned long long lo = read_uint_le(v + 4, 4);
               val = (hi << 32) | lo; }
        long long ip = val / 10000, fp = val % 10000; if (fp < 0) fp = -fp;
        snprintf(out, outcap, "%lld.%04lld", ip, fp);
        return;
    }

    /* ---- decimal / numeric ---- */
    case 0x37: case 0x3F: case 0x6A: case 0x6C: {
        const char *sign = (v[0] == 0) ? "-" : "";
        char digits[80];
        mag_to_decimal(v + 1, n - 1, digits, sizeof(digits));
        int nd = (int)strlen(digits), sc = c->scale;
        if (sc == 0) {
            snprintf(out, outcap, "%s%s", sign, digits);
        } else if (nd <= sc) {
            snprintf(out, outcap, "%s0.%0*d%s", sign, sc - nd, 0, digits);
        } else {
            snprintf(out, outcap, "%s%.*s.%s", sign, nd - sc, digits, digits + (nd - sc));
        }
        return;
    }

    /* ---- datetime family ---- */
    case 0x3D: case 0x6F:                        /* datetime(8) / DATETIMN(4 or 8) */
        if (n == 8) {
            long long days = read_int_le(v, 4);
            unsigned long long ticks = read_uint_le(v + 4, 4);
            int y, mo, d; civil_from_days(days - 25567, &y, &mo, &d);
            unsigned long long total_ms = (ticks * 1000ULL) / 300ULL;
            int hh = (int)(total_ms / 3600000), mm = (int)((total_ms % 3600000) / 60000);
            int ss = (int)((total_ms % 60000) / 1000), ms = (int)(total_ms % 1000);
            snprintf(out, outcap, "%04d-%02d-%02d %02d:%02d:%02d.%03d", y, mo, d, hh, mm, ss, ms);
            return;
        }
        /* n == 4 -> smalldatetime layout, handled by the next case */
        __attribute__((fallthrough));
    case 0x3A: {                                 /* smalldatetime(4) */
        unsigned days = (unsigned)read_uint_le(v, 2), mins = (unsigned)read_uint_le(v + 2, 2);
        int y, mo, d; civil_from_days((long long)days - 25567, &y, &mo, &d);
        snprintf(out, outcap, "%04d-%02d-%02d %02u:%02u:00", y, mo, d, mins / 60, mins % 60);
        return;
    }
    case 0x28: {                                 /* date(3): days since 0001-01-01 */
        long long days = (long long)read_uint_le(v, 3);
        int y, mo, d; civil_from_days(days - 719162, &y, &mo, &d);
        snprintf(out, outcap, "%04d-%02d-%02d", y, mo, d);
        return;
    }
    case 0x29: {                                 /* time */
        char t[32]; fmt_time(read_uint_le(v, n), c->scale, t, sizeof(t));
        snprintf(out, outcap, "%s", t);
        return;
    }
    case 0x2A: {                                 /* datetime2: time bytes + 3 date bytes */
        int tb = n - 3;
        char t[32]; fmt_time(read_uint_le(v, tb), c->scale, t, sizeof(t));
        long long days = (long long)read_uint_le(v + tb, 3);
        int y, mo, d; civil_from_days(days - 719162, &y, &mo, &d);
        snprintf(out, outcap, "%04d-%02d-%02d %s", y, mo, d, t);
        return;
    }
    case 0x2B: {                                 /* datetimeoffset: time + 3 date + 2 offset */
        int tb = n - 5;
        char t[32]; fmt_time(read_uint_le(v, tb), c->scale, t, sizeof(t));
        long long days = (long long)read_uint_le(v + tb, 3);
        int off = (int)read_int_le(v + tb + 3, 2);
        int y, mo, d; civil_from_days(days - 719162, &y, &mo, &d);
        snprintf(out, outcap, "%04d-%02d-%02d %s %+03d:%02d", y, mo, d, t, off / 60, (off < 0 ? -off : off) % 60);
        return;
    }

    /* ---- uniqueidentifier (16 bytes, MS mixed-endian layout) ---- */
    case 0x24:
        snprintf(out, outcap,
            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            v[3], v[2], v[1], v[0], v[5], v[4], v[7], v[6],
            v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
        return;

    default: break;
    }

    /* ---- character / binary by classification ---- */
    if (c->is_binary) {
        int j = 0;
        if (j < outcap - 1) out[j++] = '0';
        if (j < outcap - 1) out[j++] = 'x';
        for (int k = 0; k < n && j < outcap - 3; k++)
            j += snprintf(out + j, outcap - j, "%02X", v[k]);
        out[j] = '\0';
        return;
    }
    if (c->is_unicode) {                          /* n(var)char / ntext -> UTF-8 */
        utf8_from_utf16le(v, n, out, outcap);
        return;
    }
    /* single-byte (var)char / text -> UTF-8 via the system ANSI codepage */
    utf8_from_ansi(v, n, out, outcap);
}

/* Reads one column value out of a ROW at p (avail bytes left), formats it into
 * out, and reports how many bytes it consumed. Returns 0, or -1 on framing error. */
static int read_cell(const Column *c, const unsigned char *p, int avail,
                     char *out, int outcap, int *consumed)
{
    int i = 0, is_null = 0, vlen = 0;
    const unsigned char *v = NULL;
    unsigned char plp[CELL_MAX];

    switch (c->len_cat) {
    case LC_FIXED:
        if (avail < c->fixed_size) return -1;
        v = p; vlen = c->fixed_size; i = c->fixed_size;
        break;

    case LC_BYTE: {
        if (avail < 1) return -1;
        int len = p[0]; i = 1;
        if (len == 0) is_null = 1;                /* nullable byte types: 0 == NULL */
        else { if (avail < 1 + len) return -1; v = p + 1; vlen = len; i = 1 + len; }
        break;
    }
    case LC_USHORT: {
        if (avail < 2) return -1;
        int len = p[0] | (p[1] << 8); i = 2;
        if (len == 0xFFFF) is_null = 1;
        else { if (avail < 2 + len) return -1; v = p + 2; vlen = len; i = 2 + len; }
        break;
    }
    case LC_LONG: {                               /* TEXT/NTEXT/IMAGE: text pointer */
        if (avail < 1) return -1;
        int ptrlen = p[0];
        if (ptrlen == 0) { is_null = 1; i = 1; }
        else {
            i = 1 + ptrlen + 8;                   /* skip textptr + 8-byte timestamp */
            if (avail < i + 4) return -1;
            int dlen = (int)read_uint_le(p + i, 4); i += 4;
            if (avail < i + dlen) return -1;
            v = p + i; vlen = dlen; i += dlen;
        }
        break;
    }
    case LC_PLP: {                                /* partially length-prefixed (MAX types) */
        if (avail < 8) return -1;
        unsigned long long plplen = read_uint_le(p, 8);
        i = 8;
        if (plplen == 0xFFFFFFFFFFFFFFFFULL) { is_null = 1; }
        else {
            int total = 0;
            for (;;) {
                if (avail < i + 4) return -1;
                unsigned int clen = (unsigned int)read_uint_le(p + i, 4); i += 4;
                if (clen == 0) break;             /* PLP terminator */
                if (avail < i + (int)clen) return -1;
                if (total + (int)clen <= (int)sizeof(plp)) { memcpy(plp + total, p + i, clen); total += clen; }
                i += clen;
            }
            v = plp; vlen = total;
        }
        break;
    }
    default:
        return -1;
    }

    *consumed = i;
    if (is_null) { snprintf(out, outcap, "NULL"); return 0; }
    format_cell(c, v, vlen, out, outcap);
    return 0;
}

/* Parses a TYPE_INFO block at p into col, returning bytes consumed or -1 if the
 * type is one we don't know how to frame (in which case parsing must stop). */
static int parse_type_info(const unsigned char *p, int avail, Column *col)
{
    if (avail < 1) return -1;
    uint8_t t = p[0]; int i = 1;
    col->type = t; col->scale = 0; col->precision = 0;
    col->is_unicode = 0; col->is_binary = 0; col->max_len = 0; col->fixed_size = 0;

    switch (t) {
    /* fixed-length (no metadata, no length prefix in rows) */
    case 0x1F: col->len_cat = LC_FIXED; col->fixed_size = 0; break;  /* null */
    case 0x30: col->len_cat = LC_FIXED; col->fixed_size = 1; break;  /* tinyint */
    case 0x32: col->len_cat = LC_FIXED; col->fixed_size = 1; break;  /* bit */
    case 0x34: col->len_cat = LC_FIXED; col->fixed_size = 2; break;  /* smallint */
    case 0x38: col->len_cat = LC_FIXED; col->fixed_size = 4; break;  /* int */
    case 0x3A: col->len_cat = LC_FIXED; col->fixed_size = 4; break;  /* smalldatetime */
    case 0x3B: col->len_cat = LC_FIXED; col->fixed_size = 4; break;  /* real */
    case 0x3C: col->len_cat = LC_FIXED; col->fixed_size = 8; break;  /* money */
    case 0x3D: col->len_cat = LC_FIXED; col->fixed_size = 8; break;  /* datetime */
    case 0x3E: col->len_cat = LC_FIXED; col->fixed_size = 8; break;  /* float */
    case 0x7A: col->len_cat = LC_FIXED; col->fixed_size = 4; break;  /* smallmoney */
    case 0x7F: col->len_cat = LC_FIXED; col->fixed_size = 8; break;  /* bigint */

    /* byte-len types with a single max-length byte */
    case 0x24: case 0x26: case 0x68: case 0x6D: case 0x6E: case 0x6F:  /* guid,intn,bitn,fltn,moneyn,datetimn */
        if (avail < i + 1) return -1;
        col->max_len = p[i]; i += 1; col->len_cat = LC_BYTE; break;

    /* decimal / numeric: max-len + precision + scale */
    case 0x37: case 0x3F: case 0x6A: case 0x6C:
        if (avail < i + 3) return -1;
        col->max_len = p[i]; col->precision = p[i + 1]; col->scale = p[i + 2];
        i += 3; col->len_cat = LC_BYTE; break;

    case 0x28: col->len_cat = LC_BYTE; break;     /* date (no metadata) */

    case 0x29: case 0x2A: case 0x2B:              /* time, datetime2, datetimeoffset */
        if (avail < i + 1) return -1;
        col->scale = p[i]; i += 1; col->len_cat = LC_BYTE; break;

    /* legacy byte-len char/binary */
    case 0x2F: case 0x27:                         /* char, varchar */
        if (avail < i + 1) return -1;
        col->max_len = p[i]; i += 1; col->len_cat = LC_BYTE;
        break;
    case 0x2D: case 0x25:                         /* binary, varbinary */
        if (avail < i + 1) return -1;
        col->max_len = p[i]; i += 1; col->len_cat = LC_BYTE; col->is_binary = 1;
        break;

    /* ushort-len binary (max-len 2) */
    case 0xA5: case 0xAD:                          /* varbinary, binary */
        if (avail < i + 2) return -1;
        col->max_len = p[i] | (p[i + 1] << 8); i += 2;
        col->is_binary = 1;
        col->len_cat = (col->max_len == 0xFFFF) ? LC_PLP : LC_USHORT; break;

    /* ushort-len char (max-len 2 + 5-byte collation) */
    case 0xA7: case 0xAF:                          /* varchar, char */
        if (avail < i + 2 + 5) return -1;
        col->max_len = p[i] | (p[i + 1] << 8); i += 2 + 5;
        col->len_cat = (col->max_len == 0xFFFF) ? LC_PLP : LC_USHORT; break;
    case 0xE7: case 0xEF:                          /* nvarchar, nchar */
        if (avail < i + 2 + 5) return -1;
        col->max_len = p[i] | (p[i + 1] << 8); i += 2 + 5;
        col->is_unicode = 1;
        col->len_cat = (col->max_len == 0xFFFF) ? LC_PLP : LC_USHORT; break;

    /* long-len: text / ntext / image (max-len 4 [+5 collation] + table name) */
    case 0x23: case 0x63: {                        /* text, ntext */
        if (avail < i + 4 + 5) return -1;
        i += 4 + 5;
        if (t == 0x63) col->is_unicode = 1;
        if (avail < i + 1) return -1;
        int np = p[i]; i += 1;
        for (int k = 0; k < np; k++) {
            if (avail < i + 2) return -1;
            int cc = p[i] | (p[i + 1] << 8); i += 2 + cc * 2;
        }
        col->len_cat = LC_LONG; break;
    }
    case 0x22: {                                   /* image */
        if (avail < i + 4) return -1;
        i += 4;
        if (avail < i + 1) return -1;
        int np = p[i]; i += 1;
        for (int k = 0; k < np; k++) {
            if (avail < i + 2) return -1;
            int cc = p[i] | (p[i + 1] << 8); i += 2 + cc * 2;
        }
        col->len_cat = LC_LONG; col->is_binary = 1; break;
    }

    default:
        col->len_cat = LC_UNSUPPORTED;
        return -1;
    }
    return i;
}

/* Reads a B_VARCHAR (1-byte char count + UTF-16LE chars) into name as UTF-8.
 * Returns bytes consumed, or -1. */
static int read_bvarchar_name(const unsigned char *p, int avail, char *name, int namecap)
{
    if (avail < 1) return -1;
    int nchars = p[0];
    if (avail < 1 + nchars * 2) return -1;
    utf8_from_utf16le(p + 1, nchars * 2, name, namecap);
    return 1 + nchars * 2;
}

/* --- Table buffer management + rendering --- */

static void table_reset(Table *t)
{
    for (int r = 0; r < t->nrows; r++) {
        for (int c = 0; c < t->ncols; c++) free(t->rows[r][c]);
        free(t->rows[r]);
    }
    free(t->rows);
    t->rows = NULL; t->nrows = 0; t->cap = 0; t->ncols = 0; t->truncated = 0;
}

static char **table_new_row(Table *t)
{
    if (t->nrows >= MAX_ROWS) { t->truncated = 1; return NULL; }
    if (t->nrows >= t->cap) {
        int nc = t->cap ? t->cap * 2 : 64;
        char ***nr = realloc(t->rows, nc * sizeof(char **));
        if (!nr) return NULL;
        t->rows = nr; t->cap = nc;
    }
    char **row = calloc(t->ncols, sizeof(char *));
    if (!row) return NULL;
    t->rows[t->nrows++] = row;
    return row;
}

static void print_repeat(char ch, int n) { for (int i = 0; i < n; i++) putchar(ch); }

/* Repeat a (possibly multi-byte) glyph string n times — used for box borders. */
static void print_repeat_s(const char *s, int n) { for (int i = 0; i < n; i++) fputs(s, stdout); }

/* Display width of a UTF-8 string = number of code points (good enough for
 * Latin/Turkish text; wide CJK glyphs are undercounted). */
static int utf8_ncols(const char *s)
{
    int n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if ((*p & 0xC0) != 0x80) n++;                /* count non-continuation bytes */
    return n;
}

/* Print s truncated to at most `width` display columns (ellipsis if clipped),
 * with no padding. Returns the number of display columns actually written. */
static int print_clip(const char *s, int width)
{
    int dw = utf8_ncols(s);
    if (dw <= width) { fputs(s, stdout); return dw; }
    int keep = width > 0 ? width - 1 : 0;            /* leave 1 column for the ellipsis */
    const char *p = s;
    for (int cps = 0; *p && cps < keep; cps++) {
        unsigned char c = (unsigned char)*p;
        p += (c < 0x80) ? 1 : (c < 0xE0) ? 2 : (c < 0xF0) ? 3 : 4;
    }
    fwrite(s, 1, (size_t)(p - s), stdout);
    fputs("\xE2\x80\xA6", stdout);                   /* … */
    return width;
}

/* Print s in exactly `width` display columns, right- or left-justified. */
static void print_padded(const char *s, int width, int right)
{
    if (right) {
        int dw = utf8_ncols(s);
        if (dw < width) print_repeat(' ', width - dw);
        print_clip(s, width);
    } else {
        int printed = print_clip(s, width);
        print_repeat(' ', width - printed);
    }
}

/* Terminal width in columns (falls back to 80 when output is not a console). */
static int term_width(void)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        int w = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        if (w > 0) return w;
    }
    return 80;
}

/* Visible terminal height in rows (falls back to 24 when not a console). */
static int term_height(void)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        int h = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        if (h > 0) return h;
    }
    return 24;
}

/* True when stdout is a real console (not redirected to a file/pipe). Paging is
 * only meaningful — and only able to read a keypress — on an interactive TTY. */
static int is_console(void)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    return GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi) != 0;
}

/* ---- screenful pager ------------------------------------------------------
 * Renderers emit content lines and call pager_step() after each one. When a
 * screenful has scrolled by, we pause with a "-- more --" prompt and wait for a
 * keypress: Enter/Space shows the next page, q quits early. The pager is inert
 * (every step returns 1) when disabled, when the whole result already fits, or
 * when output is not a console. */
typedef struct { int enabled, budget, page, quit; } Pager;

static void pager_init(Pager *p, int total_lines)
{
    p->quit = 0;
    p->page = term_height() - 4;                 /* leave room for prompt + borders */
    if (p->page < 4) p->page = 4;
    p->budget  = p->page;
    p->enabled = g_pager && is_console() && total_lines > p->page;
}

/* Call after printing one content line. Returns 0 if the user asked to stop. */
static int pager_step(Pager *p)
{
    if (!p->enabled) return 1;
    if (--p->budget > 0) return 1;

    printf("%s  -- more --  (Enter/Space: next page   q: quit)%s", CLR_DIM, CLR_RESET);
    fflush(stdout);
    int ch = _getch();
    fputs("\r", stdout);                          /* wipe the prompt line, stay put */
    print_repeat(' ', 52);
    fputs("\r", stdout);
    fflush(stdout);

    if (ch == 'q' || ch == 'Q' || ch == 3) { p->quit = 1; return 0; }
    p->budget = p->page;
    return 1;
}

/* Numeric columns are right-justified (looks cleaner, like psql). */
static int col_is_numeric(uint8_t t)
{
    switch (t) {
    case 0x30: case 0x34: case 0x38: case 0x7F: case 0x26:   /* int family */
    case 0x32: case 0x68:                                    /* bit */
    case 0x3B: case 0x3E: case 0x6D:                         /* real / float */
    case 0x3C: case 0x7A: case 0x6E:                         /* money */
    case 0x37: case 0x3F: case 0x6A: case 0x6C:              /* decimal / numeric */
        return 1;
    default:
        return 0;
    }
}

#define NORMAL_CAP 60   /* max natural column width in the normal (grid) layout */
#define MIN_COL     4   /* floor a column may be shrunk to so the grid still fits */

/* Is this cell a SQL NULL? (rendered dimmed and centred-neutral.) */
static int cell_is_null(const char *s) { return s && strcmp(s, "NULL") == 0; }

/* Footer summarising a result set. When the pager stopped early, say how much of
 * the set was actually shown so a truncated view is never mistaken for the whole. */
static void print_rowcount(const Table *t, int shown, int stopped)
{
    if (stopped && shown < t->nrows)
        printf("%s(showing %d of %d rows)%s\n\n",
               CLR_DIM, shown, t->nrows, CLR_RESET);
    else
        printf("%s(%d row%s)%s%s\n\n",
               CLR_DIM, t->nrows, t->nrows == 1 ? "" : "s", CLR_RESET,
               t->truncated ? "  [truncated]" : "");
}

/* One horizontal box rule spanning every column; `l`,`mid`,`r` pick the junction
 * glyphs (top / middle / bottom flavours of the corners). */
static void render_rule(const Table *t, const int *w, const BoxChars *b,
                        const char *l, const char *mid, const char *r)
{
    fputs(CLR_DIM, stdout);
    fputs(l, stdout);
    for (int c = 0; c < t->ncols; c++) {
        print_repeat_s(b->h, w[c] + 2);
        fputs(c < t->ncols - 1 ? mid : r, stdout);
    }
    fputs(CLR_RESET, stdout);
    putchar('\n');
}

/* Prints a single vertical border glyph, dimmed. */
static void render_bar(const BoxChars *b)
{
    fputs(CLR_DIM, stdout); fputs(b->v, stdout); fputs(CLR_RESET, stdout);
}

/* Classic grid layout in a coloured box: header, separator, rows, footer.
 * w[] holds each column's display width; rows are paged a screenful at a time. */
static void render_normal(Table *t, const int *w)
{
    BoxChars b = box_chars();

    render_rule(t, w, &b, b.tl, b.tm, b.tr);         /* ┌─┬─┐ */

    render_bar(&b);                                  /* header row */
    for (int c = 0; c < t->ncols; c++) {
        putchar(' ');
        printf("%s%s", CLR_BOLD, CLR_CYAN);
        print_padded(t->cols[c].name, w[c], col_is_numeric(t->cols[c].type));
        fputs(CLR_RESET, stdout);
        putchar(' ');
        render_bar(&b);
    }
    putchar('\n');

    render_rule(t, w, &b, b.ml, b.mm, b.mr);         /* ├─┼─┤ */

    Pager pg; pager_init(&pg, t->nrows);
    int r = 0;
    for (; r < t->nrows; r++) {                       /* data rows */
        render_bar(&b);
        for (int c = 0; c < t->ncols; c++) {
            const char *cell = t->rows[r][c] ? t->rows[r][c] : "";
            int nul = cell_is_null(cell);
            putchar(' ');
            if (nul) fputs(CLR_DIM, stdout);
            print_padded(cell, w[c], col_is_numeric(t->cols[c].type));
            if (nul) fputs(CLR_RESET, stdout);
            putchar(' ');
            render_bar(&b);
        }
        putchar('\n');
        if (!pager_step(&pg)) { r++; break; }        /* user quit the pager */
    }

    render_rule(t, w, &b, b.bl, b.bm, b.br);         /* └─┴─┘ */
    print_rowcount(t, r, pg.quit);
}

/* Expanded layout (psql's \x): one "column | value" line per field, grouped
 * per record. Used for tables too wide to fit the terminal as a grid. Paged by
 * output line so very tall records don't scroll off unseen. */
static void render_expanded(Table *t)
{
    BoxChars b = box_chars();
    int namew = 0;
    for (int c = 0; c < t->ncols; c++) {
        int l = utf8_ncols(t->cols[c].name);
        if (l > namew) namew = l;
    }
    if (namew < 1)  namew = 1;
    if (namew > 30) namew = 30;

    int valw = term_width() - namew - 3;             /* "name | value" */
    if (valw < 8) valw = 8;

    Pager pg; pager_init(&pg, t->nrows * (t->ncols + 1));
    int shown = 0;
    for (int r = 0; r < t->nrows && !pg.quit; r++) {
        char label[48];
        int n = snprintf(label, sizeof label, "[ RECORD %d ]", r + 1);
        printf("%s%s%s%s", CLR_DIM, CLR_CYAN, label, CLR_RESET);
        fputs(CLR_DIM, stdout);
        for (int i = n; i < namew + 1; i++) fputs("\xe2\x94\x80", stdout);   /* ─ */
        fputs("\xe2\x94\xbc", stdout);                                       /* ┼ */
        for (int i = 0; i < valw + 1; i++) fputs("\xe2\x94\x80", stdout);
        fputs(CLR_RESET, stdout);
        putchar('\n');
        if (!pager_step(&pg)) break;

        for (int c = 0; c < t->ncols; c++) {
            printf("%s%s", CLR_BOLD, CLR_CYAN);
            print_padded(t->cols[c].name, namew, 0);
            fputs(CLR_RESET, stdout);
            fputs(" ", stdout); render_bar(&b); fputs(" ", stdout);
            const char *v = t->rows[r][c] ? t->rows[r][c] : "";
            if (cell_is_null(v)) fputs(CLR_DIM, stdout);
            print_clip(v, valw);                     /* no trailing pad */
            if (cell_is_null(v)) fputs(CLR_RESET, stdout);
            putchar('\n');
            if (!pager_step(&pg)) break;
        }
        shown = r + 1;
    }
    print_rowcount(t, shown, pg.quit);
}

static void table_render(Table *t)
{
    if (t->ncols == 0) return;

    /* natural width of each column = widest of its header and cells (display
     * cols), capped so one long text column doesn't blow up the grid. */
    int w[MAX_COLS];
    long total = 3 * t->ncols + 1;                   /* box borders + separators */
    for (int c = 0; c < t->ncols; c++) {
        int mx = utf8_ncols(t->cols[c].name);
        for (int r = 0; r < t->nrows; r++) {
            int cl = t->rows[r][c] ? utf8_ncols(t->rows[r][c]) : 0;
            if (cl > mx) mx = cl;
        }
        if (mx < 1) mx = 1;
        if (mx > NORMAL_CAP) mx = NORMAL_CAP;
        w[c] = mx;
        total += mx;
    }

    /* If the grid is a touch too wide, steal columns from the widest fields
     * (clipping their cells with an ellipsis) so the data still fits the screen
     * as a readable grid instead of dropping straight to the expanded layout. */
    int avail = term_width();
    while (total > avail) {
        int wc = -1, wmax = MIN_COL;
        for (int c = 0; c < t->ncols; c++)
            if (w[c] > wmax) { wmax = w[c]; wc = c; }
        if (wc < 0) break;                           /* nothing left to shrink */
        w[wc]--; total--;
    }

    /* Grid when it fits; otherwise fall back to the readable expanded layout. */
    if (g_expanded || total > avail)
        render_expanded(t);
    else
        render_normal(t, w);
}

/* Walks a result-set token stream and prints each result set as a table.
 * Handles COLMETADATA, ROW, NBCROW, DONE-family, ERROR/INFO/ENVCHANGE/etc. */
static void parse_result_stream(const unsigned char *tok, int len)
{
    Table t; memset(&t, 0, sizeof(t));
    int i = 0;
    int any_output = 0;

    while (i < len) {
        uint8_t type = tok[i++];

        if (type == 0x81) {                        /* COLMETADATA */
            if (t.ncols > 0 || t.nrows > 0) { table_render(&t); table_reset(&t); }
            if (i + 2 > len) break;
            int count = tok[i] | (tok[i + 1] << 8); i += 2;
            if (count == 0xFFFF) { t.ncols = 0; continue; }  /* no columns */
            if (count > MAX_COLS) count = MAX_COLS;
            t.ncols = count;
            for (int c = 0; c < count; c++) {
                if (i + 6 > len) { t.ncols = c; break; }
                i += 4;                             /* UserType (4, TDS 7.2+) */
                i += 2;                             /* Flags (2) */
                int used = parse_type_info(tok + i, len - i, &t.cols[c]);
                if (used < 0) {
                    printf("(unsupported column type 0x%02X — stopping)\n", tok[i]);
                    table_reset(&t); return;
                }
                i += used;
                int nu = read_bvarchar_name(tok + i, len - i, t.cols[c].name, sizeof(t.cols[c].name));
                if (nu < 0) { t.ncols = c; break; }
                i += nu;
            }
            any_output = 1;
        }
        else if (type == 0xD1) {                   /* ROW */
            char **row = table_new_row(&t);
            for (int c = 0; c < t.ncols; c++) {
                char cell[CELL_MAX]; int used = 0;
                if (read_cell(&t.cols[c], tok + i, len - i, cell, sizeof(cell), &used) < 0) {
                    printf("(row parse error at column %d)\n", c); table_reset(&t); return;
                }
                i += used;
                if (row) row[c] = _strdup(cell);
            }
        }
        else if (type == 0xD2) {                   /* NBCROW (null-bitmap compressed) */
            int nbytes = (t.ncols + 7) / 8;
            if (i + nbytes > len) break;
            const unsigned char *bitmap = tok + i; i += nbytes;
            char **row = table_new_row(&t);
            for (int c = 0; c < t.ncols; c++) {
                if (bitmap[c / 8] & (1 << (c % 8))) {        /* bit set -> NULL */
                    if (row) row[c] = _strdup("NULL");
                    continue;
                }
                char cell[CELL_MAX]; int used = 0;
                if (read_cell(&t.cols[c], tok + i, len - i, cell, sizeof(cell), &used) < 0) {
                    printf("(row parse error at column %d)\n", c); table_reset(&t); return;
                }
                i += used;
                if (row) row[c] = _strdup(cell);
            }
        }
        else if (type == 0xFD || type == 0xFE || type == 0xFF) {  /* DONE / DONEPROC / DONEINPROC */
            if (t.ncols > 0 || t.nrows > 0) { table_render(&t); table_reset(&t); }
            i += 12;                                /* Status(2) + CurCmd(2) + RowCount(8) */
        }
        else if (type == 0x79) {                   /* RETURNSTATUS */
            i += 4;
        }
        else if ((type & 0x30) == 0x20) {          /* variable-length token (USHORT length) */
            if (i + 2 > len) break;
            int tl = tok[i] | (tok[i + 1] << 8); i += 2;
            if (tl > len - i) tl = len - i;
            if (type == 0xAA) print_error_token(tok + i, tl);   /* ERROR — show message */
            i += tl;
        }
        else {
            printf("(unknown token 0x%02X — stopping)\n", type);
            break;
        }
    }

    if (t.ncols > 0 || t.nrows > 0) table_render(&t);
    else if (!any_output) printf("%s(command completed, no result set)%s\n\n", CLR_DIM, CLR_RESET);
    table_reset(&t);
}

/* Sends a T-SQL batch and prints the server's result. Returns 0 on success.
 * Transport (plaintext vs TLS) follows the negotiated g_encrypt. */
static int tds_exec(SSL *ssl, SOCKET s, const char *sql)
{
    int qn = (int)strlen(sql);
    int msglen = 22 + qn * 2;                      /* ALL_HEADERS(22) + UTF-16LE text */
    unsigned char *msg = malloc(msglen);
    if (!msg) return -1;

    /* ALL_HEADERS with a single Transaction Descriptor header (required by TDS 7.2+) */
    put_u32le(msg + 0, 22);                        /* TotalLength (incl. itself) */
    put_u32le(msg + 4, 18);                        /* HeaderLength */
    msg[8] = 0x02; msg[9] = 0x00;                  /* HeaderType = 0x0002 (txn descriptor) */
    memset(msg + 10, 0, 8);                        /* TransactionDescriptor = 0 */
    put_u32le(msg + 18, 1);                        /* OutstandingRequestCount = 1 */

    for (int k = 0; k < qn; k++) {                 /* query text, ASCII -> UTF-16LE */
        msg[22 + k * 2]     = (unsigned char)sql[k];
        msg[22 + k * 2 + 1] = 0x00;
    }

    /* Transport follows the negotiated encryption: TLS both ways when the whole
     * session is encrypted, plaintext both ways under ENCRYPT_OFF. */
    int rc = tds_send_message(ssl, s, g_encrypt, TDS_PKT_SQLBATCH, msg, msglen);
    free(msg);
    if (rc < 0) { printf("batch send failed: %d\n", WSAGetLastError()); return -1; }

    int rlen = 0;
    unsigned char *resp = tds_read_message(ssl, s, g_encrypt, &rlen);
    if (!resp) { printf("no response / read error\n"); return -1; }

    parse_result_stream(resp, rlen);
    free(resp);
    return 0;
}

/* Clears the console. When ANSI/VT processing is available (Windows Terminal,
 * modern conhost) it also wipes the scrollback so old output is truly gone and
 * does not accumulate. Order matters: ESC[H homes the cursor, ESC[2J clears the
 * screen (which pushes the current viewport into the scrollback on Windows
 * Terminal), and ESC[3J must come LAST so it erases that pushed content too —
 * otherwise the first \clear leaves the old lines behind. Falls back to the
 * Win32 console API when VT is unavailable. */
static void clear_screen(void)
{
    if (g_vt) {
        fputs("\x1b[H\x1b[2J\x1b[3J", stdout);
        fflush(stdout);
        return;
    }

    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(h, &csbi)) return;

    DWORD cells = (DWORD)csbi.dwSize.X * csbi.dwSize.Y;
    COORD home = {0, 0};
    DWORD written;
    FillConsoleOutputCharacterA(h, ' ', cells, home, &written);
    FillConsoleOutputAttribute(h, csbi.wAttributes, cells, home, &written);
    SetConsoleCursorPosition(h, home);
}

/* Lists the backslash meta-commands. All of tdsh's own commands start with '\';
 * anything else is sent to the server verbatim as a T-SQL batch. */
static void print_repl_help(void)
{
    printf("\n  %smeta-commands%s %s(everything else is run as T-SQL)%s\n",
           CLR_BOLD, CLR_RESET, CLR_DIM, CLR_RESET);
    printf("    %s\\help%s, %s\\?%s      show this help\n",
           CLR_CYAN, CLR_RESET, CLR_CYAN, CLR_RESET);
    printf("    %s\\x%s            toggle expanded (one-field-per-line) display\n",
           CLR_CYAN, CLR_RESET);
    printf("    %s\\pager%s        toggle screen-at-a-time paging of long results\n",
           CLR_CYAN, CLR_RESET);
    printf("    %s\\clear%s, %s\\cls%s  clear the screen\n",
           CLR_CYAN, CLR_RESET, CLR_CYAN, CLR_RESET);
    printf("    %s\\exit%s, %s\\q%s     leave tdsh  (or Ctrl+Z then Enter)\n\n",
           CLR_CYAN, CLR_RESET, CLR_CYAN, CLR_RESET);
}

/* Interactive read-eval-print loop: each entered line is sent as one batch,
 * unless it is a '\'-prefixed meta-command handled locally. */
static void run_repl(SSL *ssl, SOCKET s)
{
    char line[8192];

    /* let queries take their time; login used a short recv timeout */
    DWORD timeout = 60000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    printf("\n  %s%stdsh%s %sinteractive%s — type T-SQL and press Enter, "
           "%s\\help%s for commands.\n\n",
           CLR_BOLD, CLR_CYAN, CLR_RESET, CLR_DIM, CLR_RESET,
           CLR_CYAN, CLR_RESET);

    for (;;) {
        printf("%s%stdsh>%s ", CLR_BOLD, CLR_GREEN, CLR_RESET);
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;   /* EOF (Ctrl+Z / Ctrl+D) */

        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (n == 0) continue;

        if (line[0] == '\\') {                          /* meta-command */
            if (strcmp(line, "\\exit") == 0 || strcmp(line, "\\q") == 0) break;
            if (strcmp(line, "\\help") == 0 || strcmp(line, "\\?") == 0) {
                print_repl_help();
            } else if (strcmp(line, "\\x") == 0) {      /* toggle expanded display */
                g_expanded = !g_expanded;
                printf("  %sexpanded display %s%s\n\n", CLR_DIM,
                       g_expanded ? "on" : "off (auto)", CLR_RESET);
            } else if (strcmp(line, "\\pager") == 0) {  /* toggle result paging */
                g_pager = !g_pager;
                printf("  %spager %s%s\n\n", CLR_DIM,
                       g_pager ? "on" : "off", CLR_RESET);
            } else if (strcmp(line, "\\clear") == 0 || strcmp(line, "\\cls") == 0) {
                clear_screen();                         /* wipe screen, keep only the prompt */
            } else {
                printf("  %sunknown command %s%s%s — try %s\\help%s\n\n",
                       CLR_DIM, CLR_RESET, line, CLR_DIM, CLR_CYAN, CLR_RESET);
            }
            continue;
        }

        tds_exec(ssl, s, line);
    }
}

/* ============================================================
 *  Interactive connection form
 * ============================================================ */

/* Reads one text field. Shows the label and, when given, a [default] hint; an
 * empty Enter keeps the default. fgets gives us native line editing (backspace,
 * etc.) for free. buf is always null-terminated. */
static void read_field(const char *label, const char *def, char *buf, int cap)
{
    if (def && def[0])
        printf("  %s%-9s%s %s[%s]%s: ", CLR_BOLD, label, CLR_RESET,
               CLR_DIM, def, CLR_RESET);
    else
        printf("  %s%-9s%s: ", CLR_BOLD, label, CLR_RESET);
    fflush(stdout);

    if (!fgets(buf, cap, stdin)) { buf[0] = '\0'; }
    size_t n = strlen(buf);
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';

    if (n == 0 && def) {                     /* empty input -> take the default */
        strncpy(buf, def, cap - 1);
        buf[cap - 1] = '\0';
    }
}

/* Reads the password without echoing it: every keystroke is shown as '*' so the
 * secret never lands on screen. Handles Backspace, Enter (finish) and Ctrl+C
 * (abort). Special/arrow keys (_getch prefix 0x00/0xE0) are swallowed. */
static void read_password(const char *label, char *buf, int cap)
{
    printf("  %s%-9s%s: ", CLR_BOLD, label, CLR_RESET);
    fflush(stdout);

    int len = 0;
    for (;;) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') break;          /* Enter — done */
        if (ch == 3) { printf("\n"); exit(1); }       /* Ctrl+C — abort */
        if (ch == 0 || ch == 0xE0) { _getch(); continue; }  /* eat function/arrow key */
        if (ch == '\b' || ch == 127) {                /* Backspace — erase one '*' */
            if (len > 0) { len--; fputs("\b \b", stdout); fflush(stdout); }
            continue;
        }
        if (ch < 32) continue;                         /* ignore other control chars */
        if (len < cap - 1) {
            buf[len++] = (char)ch;
            fputc('*', stdout);
            fflush(stdout);
        }
    }
    buf[len] = '\0';
    printf("\n");
}

/* Asks for the connection details step by step and fills the caller's buffers
 * (each at least 256 bytes). Sensible defaults are offered for everything but
 * the password. */
static void prompt_connection(char *host, char *port, char *user,
                              char *pass, char *db)
{
    printf("\n  %s%stdsh%s %s— connect to SQL Server%s\n",
           CLR_BOLD, CLR_CYAN, CLR_RESET, CLR_DIM, CLR_RESET);
    printf("  %s────────────────────────────%s\n\n", CLR_DIM, CLR_RESET);

    read_field   ("Host",     "localhost", host, 256);
    read_field   ("Port",     "1433",      port, 256);
    read_field   ("Username", "sa",        user, 256);
    read_password("Password",              pass, 256);
    read_field   ("Database", "master",    db,   256);

    printf("\n  %s→%s connecting to %s%s@%s:%s/%s%s ...\n\n",
           CLR_GREEN, CLR_RESET, CLR_BOLD, user, host, port, db, CLR_RESET);
}

/* ============================================================
 *  main — orchestrator
 * ============================================================ */

int main(int argc, char *argv[])
{
  SetConsoleOutputCP(CP_UTF8);   /* render UTF-8 result data (Turkish etc.) correctly */

  /* enable ANSI escape processing so \clear can wipe the scrollback, not just
   * scroll it out of view (keeps memory/clutter from piling up). */
  {
      HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
      DWORD mode;
      if (GetConsoleMode(hout, &mode) &&
          SetConsoleMode(hout, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
          g_vt = 1;
  }

  /* Connection details. Filled either from the command line (backward-compatible
   * scripting mode) or, when no args are given, asked interactively as a form. */
  char host[256], port[256], user[256], pass[256], db[256];

  if (argc >= 6) {
      strncpy(host, argv[1], sizeof host - 1); host[sizeof host - 1] = '\0';
      strncpy(port, argv[2], sizeof port - 1); port[sizeof port - 1] = '\0';
      strncpy(user, argv[3], sizeof user - 1); user[sizeof user - 1] = '\0';
      strncpy(pass, argv[4], sizeof pass - 1); pass[sizeof pass - 1] = '\0';
      strncpy(db,   argv[5], sizeof db   - 1); db[sizeof db     - 1] = '\0';
  } else if (argc == 1) {
      prompt_connection(host, port, user, pass, db);
  } else {
      printf("Usage: %s [<host> <port> <username> <password> <database>]\n"
             "  (run with no arguments to fill in the connection form)\n", argv[0]);
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

  s = tcp_connect(host, port);
  if (s == INVALID_SOCKET)                                  goto cleanup;

  if (tds_send_prelogin(s, recvbuf, RECV_BUFLEN) != 0)      goto cleanup;

  ssl = ssl_setup(&ctx);
  if (!ssl)                                                 goto cleanup;

  if (tds_tls_handshake(ssl, s, recvbuf, RECV_BUFLEN) != 0) goto cleanup;

  printf("TLS channel established\n");

  if (Login7(ssl, s, user, pass, db) != 0)
      goto cleanup;

  printf("Login Success\n");

  run_repl(ssl, s);   /* interactive T-SQL loop (TLS or plaintext per g_encrypt) */
  rc = 0;

cleanup:
  if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }  /* BIOs are freed together with ssl */
  if (ctx) SSL_CTX_free(ctx);
  if (s != INVALID_SOCKET) closesocket(s);
  WSACleanup();
  return rc;
}