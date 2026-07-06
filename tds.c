#include "tdsh.h"
#include "sspi.h"

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
SOCKET tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
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

    if (plat_connect_timeout(s, result->ai_addr, (int)result->ai_addrlen, 10000) != 0) {
        printf("connect() failed/timed out: %d\n", WSAGetLastError());
        closesocket(s);
        freeaddrinfo(result);
        return INVALID_SOCKET;
    }

    plat_set_keepalive(s);          /* detect a silently dropped peer */
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
int tds_send_prelogin(SOCKET s, unsigned char *recvbuf, int recvbuflen)
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
SSL *ssl_setup(SSL_CTX **out_ctx)
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
int tds_tls_handshake(SSL *ssl, SOCKET s, unsigned char *recvbuf, int recvbuflen)
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
void print_error_token(const unsigned char *p, int len)
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

/* Decodes and prints a TDS INFO (0xAB) token — PRINT output and informational
 * server messages (e.g. "Changed database context…"). Same body layout as ERROR
 * (Number(4) State(1) Class(1) then MsgText as a US_VARCHAR); shown dimmed, not
 * as an error. */
void print_info_token(const unsigned char *p, int len)
{
    int off = 4 + 1 + 1;                 /* skip Number, State, Class */
    if (off + 2 > len) return;
    int msg_chars = p[off] | (p[off + 1] << 8);
    off += 2;
    if (off + msg_chars * 2 > len)       /* clamp defensively */
        msg_chars = (len - off) / 2;

    char msg[2048];
    utf8_from_utf16le(p + off, msg_chars * 2, msg, sizeof msg);
    printf("%s%s%s\n", CLR_DIM, msg, CLR_RESET);
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
int Login7(SSL *ssl, SOCKET s,
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

  plat_set_recv_timeout(s, 15000);

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
 *  Integrated (Windows) authentication — LOGIN7 with fIntSecurity + SSPI
 *
 *  EXPERIMENTAL / Windows-only. Requires a SQL Server that accepts Windows auth;
 *  it has not been validated against a domain-joined server. The flow: send a
 *  LOGIN7 whose SSPI field carries the first SSPI (Negotiate) token, then loop —
 *  each server SSPI token (0xED) is fed back into SSPI, and the reply is sent as
 *  a 0x11 SSPI packet — until a LOGINACK arrives.
 * ============================================================ */

#ifdef _WIN32

/* Writes a raw-byte LOGIN7 field (offset + byte length), like write_field but
 * without the UTF-16 char-count doubling — used for the binary SSPI blob. */
static void write_field_bytes(unsigned char *login7, int *table_pos, int *data_pos,
                              const unsigned char *data, int nbytes)
{
    login7[*table_pos + 0] = (*data_pos) & 0xFF;
    login7[*table_pos + 1] = (*data_pos >> 8) & 0xFF;
    login7[*table_pos + 2] = nbytes & 0xFF;
    login7[*table_pos + 3] = (nbytes >> 8) & 0xFF;
    if (nbytes > 0) memcpy(login7 + *data_pos, data, nbytes);
    *table_pos += 4;
    *data_pos  += nbytes;
}

/* Walks a login-response token stream: sets *login_ok on LOGINACK, prints ERROR
 * tokens, and captures the latest SSPI (0xED) challenge into *sspi (malloc'd). */
static void scan_auth_response(const unsigned char *tok, int tok_len,
                               int *login_ok, unsigned char **sspi, int *sspi_len)
{
    *login_ok = 0; *sspi = NULL; *sspi_len = 0;
    int i = 0;
    while (i < tok_len) {
        unsigned char type = tok[i++];
        if ((type & 0x30) == 0x20) {                 /* variable-length token */
            if (i + 2 > tok_len) break;
            int len = tok[i] | (tok[i + 1] << 8); i += 2;
            if (len > tok_len - i) len = tok_len - i;
            if (type == 0xAD)      *login_ok = 1;                    /* LOGINACK */
            else if (type == 0xAA) print_error_token(tok + i, len); /* ERROR */
            else if (type == 0xED) {                                /* SSPI challenge */
                free(*sspi);
                *sspi = malloc(len ? len : 1);
                if (*sspi) { memcpy(*sspi, tok + i, len); *sspi_len = len; }
            }
            i += len;
        } else if (type == 0xFD || type == 0xFE || type == 0xFF) {
            i += 12;
        } else {
            break;
        }
    }
}

/* Sends one SSPI (0x11) packet carrying an outbound SSPI token. */
static int send_sspi_packet(SSL *ssl, SOCKET s, const unsigned char *tok, int toklen)
{
    unsigned char *pkt = malloc(TDS_HEADER_LEN + toklen);
    if (!pkt) return -1;
    tds_build_header(pkt, TDS_PKT_SSPI, toklen);
    memcpy(pkt + TDS_HEADER_LEN, tok, toklen);
    int rc = tds_send_app_data(ssl, s, pkt, TDS_HEADER_LEN + toklen);
    free(pkt);
    return rc;
}

#endif /* _WIN32 */

int Login7_integrated(SSL *ssl, SOCKET s, const char *host, const char *port,
                      const char *database)
{
#ifndef _WIN32
    (void)ssl; (void)s; (void)host; (void)port; (void)database;
    printf("integrated (Windows) authentication is only available on Windows\n");
    return -1;
#else
    if (!sspi_supported()) { printf("SSPI is not available\n"); return -1; }

    char spn[600];
    snprintf(spn, sizeof spn, "MSSQLSvc/%s:%s", host, port);   /* SQL Server SPN */

    SspiState *st = sspi_new();
    if (!st) { printf("sspi_new failed\n"); return -1; }

    unsigned char *tok = NULL; int toklen = 0;
    if (sspi_first(st, spn, &tok, &toklen) != 0) { sspi_free(st); return -1; }

    /* Build LOGIN7: fIntSecurity set, empty UserName/Password, SSPI = first token. */
    size_t dlen = strlen(database);
    if (dlen >= U16_FIELD_MAX || 94 + dlen * 2 + (size_t)toklen + 32 > LOGIN7_BUFLEN) {
        printf("integrated LOGIN7 too large\n"); free(tok); sspi_free(st); return -1;
    }
    uint16_t u16_database[U16_FIELD_MAX];
    ascii_to_utf16le(database, u16_database, U16_FIELD_MAX);

    unsigned char login7[LOGIN7_BUFLEN];
    memset(login7, 0, sizeof login7);
    memcpy(login7, LOGIN7_HEADER, sizeof LOGIN7_HEADER);
    login7[25] |= 0x80;                             /* OptionFlags2: fIntSecurity */

    int data_pos = 94, table_pos = 36;
    write_field(login7, &table_pos, &data_pos, NULL, 0);                    /* HostName */
    write_field(login7, &table_pos, &data_pos, NULL, 0);                    /* UserName (empty) */
    write_field(login7, &table_pos, &data_pos, NULL, 0);                    /* Password (empty) */
    write_field(login7, &table_pos, &data_pos, NULL, 0);                    /* AppName */
    write_field(login7, &table_pos, &data_pos, NULL, 0);                    /* ServerName */
    write_field(login7, &table_pos, &data_pos, NULL, 0);                    /* Unused */
    write_field(login7, &table_pos, &data_pos, NULL, 0);                    /* CltIntName */
    write_field(login7, &table_pos, &data_pos, NULL, 0);                    /* Language */
    write_field(login7, &table_pos, &data_pos, u16_database, (int)dlen);    /* Database */
    memset(login7 + table_pos, 0, 6); table_pos += 6;                      /* ClientID */
    write_field_bytes(login7, &table_pos, &data_pos, tok, toklen);          /* SSPI */
    write_field(login7, &table_pos, &data_pos, NULL, 0);                    /* AtchDBFile */
    write_field(login7, &table_pos, &data_pos, NULL, 0);                    /* ChangePassword */
    memset(login7 + table_pos, 0, 4); table_pos += 4;                      /* SSPILong */
    free(tok); tok = NULL;

    login7[0] = data_pos & 0xFF;         login7[1] = (data_pos >> 8) & 0xFF;
    login7[2] = (data_pos >> 16) & 0xFF; login7[3] = (data_pos >> 24) & 0xFF;

    unsigned char *pkt = malloc(TDS_HEADER_LEN + data_pos);
    if (!pkt) { sspi_free(st); return -1; }
    tds_build_header(pkt, TDS_PKT_LOGIN7, data_pos);
    memcpy(pkt + TDS_HEADER_LEN, login7, data_pos);
    int sent = tds_send_app_data(ssl, s, pkt, TDS_HEADER_LEN + data_pos);
    free(pkt);
    if (sent <= 0) { printf("integrated LOGIN7 send failed\n"); sspi_free(st); return -1; }

    plat_set_recv_timeout(s, 15000);

    for (int round = 0; round < 10; round++) {
        int rlen = 0;
        unsigned char *resp = tds_read_message(ssl, s, g_encrypt, &rlen);
        if (!resp) { printf("no login response\n"); sspi_free(st); return -1; }

        int login_ok = 0; unsigned char *chal = NULL; int chal_len = 0;
        scan_auth_response(resp, rlen, &login_ok, &chal, &chal_len);
        free(resp);

        if (login_ok) { free(chal); sspi_free(st); return 0; }       /* success */
        if (!chal) { printf("integrated login failed (no LOGINACK)\n"); sspi_free(st); return -1; }

        unsigned char *out = NULL; int outlen = 0, done = 0;
        int rc = sspi_next(st, spn, chal, chal_len, &out, &outlen, &done);
        free(chal);
        if (rc != 0) { free(out); sspi_free(st); return -1; }

        if (outlen > 0 && send_sspi_packet(ssl, s, out, outlen) <= 0) {
            printf("SSPI packet send failed\n"); free(out); sspi_free(st); return -1;
        }
        free(out);
        /* loop to read the next challenge or the LOGINACK */
    }

    printf("integrated login did not complete\n");
    sspi_free(st);
    return -1;
#endif
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
void put_u32le(unsigned char *p, uint32_t v)
{
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
unsigned long long read_uint_le(const unsigned char *v, int n)
{
    unsigned long long u = 0;
    for (int k = 0; k < n; k++) u |= (unsigned long long)v[k] << (8 * k);
    return u;
}
long long read_int_le(const unsigned char *v, int n)   /* signed, sign-extended */
{
    unsigned long long u = read_uint_le(v, n);
    if (n < 8 && (u & (1ULL << (8 * n - 1))))
        u |= ~((1ULL << (8 * n)) - 1);
    return (long long)u;
}
unsigned long long pow10_ull(int e)
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
int tds_send_message(SSL *ssl, SOCKET s, int enc, unsigned char type,
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
/* Classifies a failed recv: 0 return = orderly close (lost); a timeout/would-block
 * error is recoverable (just no data in time); anything else = lost. */
static int conn_lost_from(int r)
{
    if (r == 0) return 1;
    int e = WSAGetLastError();
    if (e == SOCK_ETIMEDOUT || e == SOCK_EWOULDBLOCK) return 0;
    return 1;
}

unsigned char *tds_read_message(SSL *ssl, SOCKET s, int enc, int *outlen)
{
    int cap = 65536, total = 0;
    unsigned char *buf = malloc(cap);
    unsigned char hdr[TDS_HEADER_LEN];
    if (!buf) return NULL;
    g_conn_lost = 0;

    for (;;) {
        int r = xfer_recv_all(ssl, s, enc, hdr, TDS_HEADER_LEN);
        if (r <= 0) { g_conn_lost = conn_lost_from(r); free(buf); return NULL; }

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
            int r2 = xfer_recv_all(ssl, s, enc, buf + total, payload);
            if (r2 <= 0) { g_conn_lost = conn_lost_from(r2); free(buf); return NULL; }
            total += payload;
        }
        if (hdr[1] & TDS_STATUS_EOM) break;   /* last packet of the message */
    }

    *outlen = total;
    return buf;
}
