/*
 * platform.h — OS abstraction for tdsh.
 *
 * Windows is the primary target; the POSIX branch keeps the source buildable on
 * Linux/Unix (BSD sockets, termios raw input, ioctl terminal size, dependency-
 * free codepage conversion). Windows-flavoured names (SOCKET, closesocket,
 * WSAGetLastError, _getch, DWORD, _stricmp, _strdup) are provided on POSIX so the
 * shared code needs no per-call #ifdefs.
 */

#ifndef PLATFORM_H
#define PLATFORM_H

/* Enable POSIX.1-2008 APIs (strdup, clock_gettime) on Unix. Must precede any
 * system header, and platform.h is the first include everywhere. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <conio.h>            /* _getch */

#else  /* ---- POSIX ---- */

  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <errno.h>
  #include <termios.h>
  #include <sys/ioctl.h>
  #include <sys/time.h>    /* struct timeval for SO_RCVTIMEO */
  #include <strings.h>     /* strcasecmp */

  typedef int SOCKET;
  #define INVALID_SOCKET     (-1)
  #define SOCKET_ERROR       (-1)
  #define closesocket        close
  #define WSAGetLastError()  (errno)

  #include <fcntl.h>
  #include <sys/select.h>

  typedef uint32_t DWORD;

  #define _stricmp  strcasecmp
  #define _strdup   strdup
  #define _getch    plat_getch   /* our termios-based raw reader */

#endif

/* Socket error codes used for resilience checks, normalised across OSes. */
#ifdef _WIN32
  #define SOCK_EWOULDBLOCK  WSAEWOULDBLOCK
  #define SOCK_ETIMEDOUT    WSAETIMEDOUT
  #define SOCK_EINPROGRESS  WSAEWOULDBLOCK   /* non-blocking connect: WSAEWOULDBLOCK */
#else
  #define SOCK_EWOULDBLOCK  EWOULDBLOCK
  #define SOCK_ETIMEDOUT    ETIMEDOUT
  #define SOCK_EINPROGRESS  EINPROGRESS
#endif

/* ---- platform.c ---- */

int    plat_net_init(void);                 /* WSAStartup on Windows, no-op elsewhere; 0 = ok */
void   plat_net_cleanup(void);
void   plat_console_init(void);             /* UTF-8 output + ANSI/VT; sets g_vt */
int    plat_getch(void);                    /* one raw keystroke (Win maps to _getch) */
double plat_now_ms(void);                   /* monotonic clock, milliseconds (\timing) */
void   plat_set_recv_timeout(SOCKET s, int ms);
void   plat_set_keepalive(SOCKET s);        /* enable TCP keep-alive */
void   plat_set_nonblocking(SOCKET s, int on);
int    plat_connect_timeout(SOCKET s, const struct sockaddr *addr, int addrlen, int ms);

int    term_width(void);                    /* terminal columns (80 fallback) */
int    term_height(void);                   /* terminal rows (24 fallback) */
int    is_console(void);                    /* stdout is an interactive terminal */
void   clear_screen(void);                  /* \clear */

/* Text conversion (Windows uses the Win32 codepage APIs; POSIX is dependency-free
 * best-effort). */
int    plat_utf8_to_utf16le(const char *utf8, unsigned char **out); /* returns UTF-16 code units; *out malloc'd LE bytes */
void   plat_ansi_to_utf8(int codepage, const unsigned char *v, int n, char *out, int outcap);
int    plat_lcid_codepage(unsigned int lcid);

#endif /* PLATFORM_H */
