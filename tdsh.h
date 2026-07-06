/*
 * tdsh.h — shared declarations for the tdsh TDS client.
 *
 * Every translation unit includes this: the system headers, protocol/limit
 * constants, the result-set types (Column/Table), the global session flags,
 * and the prototypes of every function that is called across module boundaries.
 *
 * Modules:
 *   tds.c     — TCP + TDS transport, TLS-in-TDS, pre-login, LOGIN7, low-level I/O
 *   format.c  — value formatting and TYPE_INFO / row-cell parsing
 *   render.c  — display-width math, box tables, pager, result-stream walk
 *   repl.c    — query execution, meta-commands, REPL, connection form
 *   main.c    — orchestration + global definitions
 */

#ifndef TDSH_H
#define TDSH_H

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
#include <ctype.h>    /* isspace/tolower — meta-command + GO parsing */
#include <conio.h>    /* _getch — read password/editor keystrokes without echo */

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

#define MAX_COLS   1024
#define CELL_MAX   4096   /* max formatted cell / assembled PLP value */
#define MAX_ROWS   100000 /* safety cap on buffered rows per result set */

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

#define DEBUG 0                 /* 1: diagnostic output on, 0: off */
#define dbg(...) do { if (DEBUG) printf(__VA_ARGS__); } while (0)

/* ---- Global session flags (defined in main.c) ---- */

/* 1 => the whole session is TLS-encrypted after the handshake, so query
 * traffic must go through SSL_read/SSL_write. Set from the pre-login response. */
extern int g_encrypt;

/* 1 => force expanded (one field per line) result display; 0 => auto (expanded
 * only when a table is too wide for the terminal). Toggled with \x in the REPL. */
extern int g_expanded;

/* 1 => ANSI escape (virtual terminal) processing is enabled on the console. */
extern int g_vt;

/* 1 => page long result sets one screen at a time; 0 => dump everything. */
extern int g_pager;

/* When non-NULL, result sets are written to this file as delimited text
 * (CSV/TSV) instead of the box grid. Set by \o, delimiter picked from the
 * file extension. Defined in repl.c, read by render.c's table_render. */
extern FILE *g_out;
extern char  g_out_delim;

/* ANSI SGR codes; expand to "" when VT processing is off so output still reads. */
#define CLR_RESET  (g_vt ? "\x1b[0m"  : "")
#define CLR_BOLD   (g_vt ? "\x1b[1m"  : "")
#define CLR_DIM    (g_vt ? "\x1b[2m"  : "")
#define CLR_CYAN   (g_vt ? "\x1b[36m" : "")
#define CLR_GREEN  (g_vt ? "\x1b[32m" : "")
#define CLR_RED    (g_vt ? "\x1b[31m" : "")
#define CLR_YELLOW (g_vt ? "\x1b[33m" : "")
#define CLR_BLUE   (g_vt ? "\x1b[34m" : "")

/* ---- Result-set types ---- */

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

/* ---- Cross-module prototypes ---- */

/* tds.c */
SOCKET tcp_connect(const char *host, const char *port);
int    tds_send_prelogin(SOCKET s, unsigned char *recvbuf, int recvbuflen);
SSL   *ssl_setup(SSL_CTX **out_ctx);
int    tds_tls_handshake(SSL *ssl, SOCKET s, unsigned char *recvbuf, int recvbuflen);
int    Login7(SSL *ssl, SOCKET s, const char *username, const char *password, const char *database);
int    tds_send_message(SSL *ssl, SOCKET s, int enc, unsigned char type,
                        const unsigned char *data, int datalen);
unsigned char *tds_read_message(SSL *ssl, SOCKET s, int enc, int *outlen);
void   put_u32le(unsigned char *p, uint32_t v);
void   print_error_token(const unsigned char *p, int len);
unsigned long long read_uint_le(const unsigned char *v, int n);
long long          read_int_le(const unsigned char *v, int n);
unsigned long long pow10_ull(int e);

/* format.c */
void utf8_from_utf16le(const unsigned char *v, int nbytes, char *out, int outcap);
int  read_cell(const Column *c, const unsigned char *p, int avail,
               char *out, int outcap, int *consumed);
int  parse_type_info(const unsigned char *p, int avail, Column *col);
int  read_bvarchar_name(const unsigned char *p, int avail, char *name, int namecap);

/* render.c */
void parse_result_stream(const unsigned char *tok, int len);
int  is_console(void);

/* repl.c */
void run_repl(SSL *ssl, SOCKET s);
void prompt_connection(char *host, char *port, char *user, char *pass, char *db);

#endif /* TDSH_H */
