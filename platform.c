#include "tdsh.h"
#include <time.h>

/* ============================================================
 *  Network init / cleanup
 * ============================================================ */

int plat_net_init(void)
{
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("WSAStartup failed\n"); return -1; }
#endif
    return 0;
}

void plat_net_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

/* ============================================================
 *  Console setup: UTF-8 output + ANSI/VT escape processing
 * ============================================================ */

void plat_console_init(void)
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);              /* render UTF-8 result data correctly */
    HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(hout, &mode) &&
        SetConsoleMode(hout, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        g_vt = 1;
#else
    g_vt = isatty(STDOUT_FILENO) ? 1 : 0;     /* Unix terminals speak ANSI natively */
#endif
}

/* ============================================================
 *  Terminal geometry / interactivity
 * ============================================================ */

int term_width(void)
{
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        int w = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        if (w > 0) return w;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
#endif
    return 80;
}

int term_height(void)
{
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        int h = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        if (h > 0) return h;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) return ws.ws_row;
#endif
    return 24;
}

int is_console(void)
{
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    return GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi) != 0;
#else
    return isatty(STDOUT_FILENO);
#endif
}

/* Clears the screen (and scrollback where possible). With VT available this is
 * pure ANSI; on Windows without VT it falls back to the console API. ESC[3J is
 * emitted last so the first clear also wipes the scrollback that ESC[2J pushes
 * there on Windows Terminal. */
void clear_screen(void)
{
    if (g_vt) {
        fputs("\x1b[H\x1b[2J\x1b[3J", stdout);
        fflush(stdout);
        return;
    }
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(h, &csbi)) return;
    DWORD cells = (DWORD)csbi.dwSize.X * csbi.dwSize.Y;
    COORD home = {0, 0};
    DWORD written;
    FillConsoleOutputCharacterA(h, ' ', cells, home, &written);
    FillConsoleOutputAttribute(h, csbi.wAttributes, cells, home, &written);
    SetConsoleCursorPosition(h, home);
#endif
}

/* ============================================================
 *  Raw keystroke input
 * ============================================================ */

#ifndef _WIN32
/* POSIX _getch: read one keystroke in raw mode without echo. Cursor/navigation
 * keys arrive as ANSI escape sequences (ESC [ A ...); we translate them to the
 * same two-step codes conio's _getch returns on Windows (a 0xE0 lead byte, then
 * the scan code on the next call), so the line editor needs no per-OS branch. */
int plat_getch(void)
{
    static int pending = -1;
    if (pending >= 0) { int c = pending; pending = -1; return c; }

    struct termios old, raw;
    if (tcgetattr(STDIN_FILENO, &old) != 0) { int c = getchar(); return c == EOF ? 26 : c; }
    raw = old;
    raw.c_lflag &= ~(ICANON | ECHO | ISIG);   /* raw; deliver Ctrl+C/Z as bytes 3/26 */
    raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);

    unsigned char b;
    int n = read(STDIN_FILENO, &b, 1);
    int ret;
    if (n <= 0) {
        ret = 26;                              /* EOF -> Ctrl+Z */
    } else if (b == 27) {                       /* ESC: possible nav sequence */
        unsigned char s0;
        if (read(STDIN_FILENO, &s0, 1) == 1 && (s0 == '[' || s0 == 'O')) {
            unsigned char s1;
            if (read(STDIN_FILENO, &s1, 1) == 1) {
                int code = -1;
                switch (s1) {
                case 'A': code = 0x48; break;  /* Up    */
                case 'B': code = 0x50; break;  /* Down  */
                case 'C': code = 0x4D; break;  /* Right */
                case 'D': code = 0x4B; break;  /* Left  */
                case 'H': code = 0x47; break;  /* Home  */
                case 'F': code = 0x4F; break;  /* End   */
                case '3': { unsigned char t; ssize_t r = read(STDIN_FILENO,&t,1); (void)r; code = 0x53; } break; /* Del */
                case '1': case '7': { unsigned char t; ssize_t r = read(STDIN_FILENO,&t,1); (void)r; code = 0x47; } break; /* Home */
                case '4': case '8': { unsigned char t; ssize_t r = read(STDIN_FILENO,&t,1); (void)r; code = 0x4F; } break; /* End */
                default: code = -1;
                }
                if (code >= 0) { pending = code; ret = 0xE0; }
                else ret = 27;
            } else ret = 27;
        } else ret = 27;
    } else {
        ret = b;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    return ret;
}
#endif

/* ============================================================
 *  Monotonic clock (\timing) and socket recv timeout
 * ============================================================ */

double plat_now_ms(void)
{
#ifdef _WIN32
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1.0e6;
#endif
}

void plat_set_recv_timeout(SOCKET s, int ms)
{
#ifdef _WIN32
    DWORD t = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof t);
#else
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv, sizeof tv);
#endif
}

/* Enable TCP keep-alive so a silently dropped peer is eventually detected. */
void plat_set_keepalive(SOCKET s)
{
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&yes, sizeof yes);
#if !defined(_WIN32) && defined(TCP_KEEPIDLE)
    int idle = 30, intvl = 10, cnt = 3;   /* best-effort tuning where supported */
    setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE,  &idle,  sizeof idle);
    setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
    setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof cnt);
#endif
}

void plat_set_nonblocking(SOCKET s, int on)
{
#ifdef _WIN32
    u_long mode = on ? 1 : 0;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int fl = fcntl(s, F_GETFL, 0);
    if (fl < 0) return;
    fcntl(s, F_SETFL, on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
#endif
}

/* connect() with a timeout: connect non-blocking, wait for writability, then
 * check SO_ERROR. Leaves the socket blocking on return. 0 = ok, -1 = failed. */
int plat_connect_timeout(SOCKET s, const struct sockaddr *addr, int addrlen, int ms)
{
    plat_set_nonblocking(s, 1);
    int rc = connect(s, addr, addrlen);
    if (rc == 0) { plat_set_nonblocking(s, 0); return 0; }   /* connected at once */

    if (WSAGetLastError() != SOCK_EINPROGRESS) { plat_set_nonblocking(s, 0); return -1; }

    /* Watch both write and exception sets: a successful connect makes the socket
     * writable, while a refused/failed connect signals the exception set on
     * Windows (and sets SO_ERROR everywhere). */
    fd_set wf, ef; FD_ZERO(&wf); FD_ZERO(&ef); FD_SET(s, &wf); FD_SET(s, &ef);
    struct timeval tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    int sel = select((int)s + 1, NULL, &wf, &ef, &tv);
    plat_set_nonblocking(s, 0);
    if (sel <= 0) return -1;                          /* timed out or select error */

    int soerr = 0; socklen_t l = sizeof soerr;
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &l) != 0 || soerr != 0)
        return -1;                                   /* connect refused/failed */
    return 0;
}

/* ============================================================
 *  Text conversion
 * ============================================================ */

/* UTF-8 -> UTF-16LE. Returns the number of UTF-16 code units; *out is a malloc'd
 * little-endian byte buffer (units*2 bytes), which the caller frees. */
int plat_utf8_to_utf16le(const char *utf8, unsigned char **out)
{
#ifdef _WIN32
    int wn = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);  /* incl. null */
    if (wn <= 0) { *out = NULL; return 0; }
    wchar_t *wbuf = malloc((size_t)wn * sizeof(wchar_t));
    if (!wbuf) { *out = NULL; return 0; }
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wbuf, wn);
    *out = (unsigned char *)wbuf;      /* wchar_t is 16-bit LE on Windows */
    return wn - 1;
#else
    size_t slen = strlen(utf8);
    unsigned char *buf = malloc(slen * 4 + 4);
    if (!buf) { *out = NULL; return 0; }
    int units = 0;
    const unsigned char *p = (const unsigned char *)utf8;
    while (*p) {
        unsigned int cp; unsigned char c = *p;
        if (c < 0x80) { cp = c; p += 1; }
        else if ((c & 0xE0) == 0xC0 && (p[1] & 0xC0) == 0x80) { cp = ((c & 0x1F) << 6) | (p[1] & 0x3F); p += 2; }
        else if ((c & 0xF0) == 0xE0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) { cp = ((c & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F); p += 3; }
        else if ((c & 0xF8) == 0xF0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) { cp = ((c & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F); p += 4; }
        else { cp = c; p += 1; }
        if (cp <= 0xFFFF) {
            buf[units * 2] = cp & 0xFF; buf[units * 2 + 1] = (cp >> 8) & 0xFF; units++;
        } else {
            cp -= 0x10000;
            unsigned int hi = 0xD800 + (cp >> 10), lo = 0xDC00 + (cp & 0x3FF);
            buf[units * 2] = hi & 0xFF; buf[units * 2 + 1] = (hi >> 8) & 0xFF; units++;
            buf[units * 2] = lo & 0xFF; buf[units * 2 + 1] = (lo >> 8) & 0xFF; units++;
        }
    }
    *out = buf;
    return units;
#endif
}

/* Legacy single-byte (collation codepage) bytes -> UTF-8. */
void plat_ansi_to_utf8(int codepage, const unsigned char *v, int n, char *out, int outcap)
{
#ifdef _WIN32
    UINT cp = codepage > 0 ? (UINT)codepage : CP_ACP;
    wchar_t wbuf[CELL_MAX];
    int wn = MultiByteToWideChar(cp, 0, (const char *)v, n, wbuf, CELL_MAX);
    if (wn <= 0) { int cpy = n < outcap - 1 ? n : outcap - 1; memcpy(out, v, cpy); out[cpy] = '\0'; return; }
    int bn = WideCharToMultiByte(CP_UTF8, 0, wbuf, wn, out, outcap - 1, NULL, NULL);
    if (bn < 0) bn = 0;
    out[bn] = '\0';
#else
    /* Dependency-free best effort: treat high bytes as Latin-1 code points. Good
     * for the ASCII range and most of CP125x; the 0x80-0x9F window may differ. */
    (void)codepage;
    int j = 0;
    for (int i = 0; i < n && j < outcap - 3; i++) {
        unsigned int u = v[i];
        if (u < 0x80) out[j++] = (char)u;
        else { out[j++] = (char)(0xC0 | (u >> 6)); out[j++] = (char)(0x80 | (u & 0x3F)); }
    }
    out[j] = '\0';
#endif
}

/* Windows ANSI code page for a locale id (used for Windows collations). */
int plat_lcid_codepage(unsigned int lcid)
{
#ifdef _WIN32
    char buf[16];
    if (GetLocaleInfoA(MAKELCID(lcid, SORT_DEFAULT), LOCALE_IDEFAULTANSICODEPAGE, buf, sizeof buf)) {
        int cp = atoi(buf);
        if (cp > 0) return cp;
    }
    return 0;
#else
    switch (lcid & 0x3FF) {           /* primary language id -> common ANSI CP */
    case 0x09: return 1252;           /* English  */
    case 0x0C: return 1252;           /* French   */
    case 0x07: return 1252;           /* German   */
    case 0x0A: return 1252;           /* Spanish  */
    case 0x1F: return 1254;           /* Turkish  */
    case 0x19: return 1251;           /* Russian  */
    case 0x08: return 1253;           /* Greek    */
    case 0x05: return 1250;           /* Czech    */
    case 0x0E: return 1250;           /* Hungarian*/
    case 0x15: return 1250;           /* Polish   */
    default:   return 1252;
    }
#endif
}
