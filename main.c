#include "tdsh.h"

/* ---- Global session flags (declared extern in tdsh.h) ---- */
int g_encrypt  = 0;
int g_expanded = 0;
int g_vt       = 0;
int g_pager    = 1;

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