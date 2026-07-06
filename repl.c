#include "tdsh.h"

/* Query execution, meta-commands, the line editor, the REPL, and the
 * interactive connection form. */

#define BATCH_MAX 65536         /* max accumulated multi-line batch */
#define HIST_MAX  256           /* command-history ring capacity */
#define LINE_MAX  8192          /* one physical input line */

/* --- \o output sink (declared extern in tdsh.h, read by render.c) --- */
FILE *g_out       = NULL;
char  g_out_delim = ',';

/* 1 => print each batch's elapsed time (toggled with \timing). */
static int g_timing = 0;

/* forward declarations for helpers defined further down */
static int  tds_exec(SSL *ssl, SOCKET s, const char *sql);
static void run_batch(SSL *ssl, SOCKET s, const char *sql);
static void clear_screen(void);
static void print_repl_help(void);
static int  handle_meta(SSL *ssl, SOCKET s, char *line);
static int  read_line_edit(const char *prompt, char *buf, int cap);
static void hist_push(const char *line);

/* Sends a T-SQL batch and prints the server's result. Returns 0 on success.
 * Transport (plaintext vs TLS) follows the negotiated g_encrypt. */
static int tds_exec(SSL *ssl, SOCKET s, const char *sql)
{
    /* The batch text arrives as UTF-8 (console output CP + editor input); convert
     * it to UTF-16LE properly so multi-byte characters survive, not just ASCII. */
    int wn = MultiByteToWideChar(CP_UTF8, 0, sql, -1, NULL, 0);   /* incl. null */
    if (wn <= 0) wn = 1;
    int wchars = wn - 1;                           /* UTF-16 code units, sans null */

    int msglen = 22 + wchars * 2;                  /* ALL_HEADERS(22) + UTF-16LE text */
    unsigned char *msg = malloc(msglen > 22 ? msglen : 22);
    if (!msg) return -1;

    /* ALL_HEADERS with a single Transaction Descriptor header (required by TDS 7.2+) */
    put_u32le(msg + 0, 22);                        /* TotalLength (incl. itself) */
    put_u32le(msg + 4, 18);                        /* HeaderLength */
    msg[8] = 0x02; msg[9] = 0x00;                  /* HeaderType = 0x0002 (txn descriptor) */
    memset(msg + 10, 0, 8);                        /* TransactionDescriptor = 0 */
    put_u32le(msg + 18, 1);                        /* OutstandingRequestCount = 1 */

    if (wchars > 0) {
        wchar_t *wbuf = malloc((size_t)wn * sizeof(wchar_t));
        if (!wbuf) { free(msg); return -1; }
        MultiByteToWideChar(CP_UTF8, 0, sql, -1, wbuf, wn);
        for (int k = 0; k < wchars; k++) {         /* UTF-16 host -> little-endian bytes */
            msg[22 + k * 2]     = (unsigned char)(wbuf[k] & 0xFF);
            msg[22 + k * 2 + 1] = (unsigned char)((wbuf[k] >> 8) & 0xFF);
        }
        free(wbuf);
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

/* Runs one batch, timing it when \timing is on (QueryPerformanceCounter). */
static void run_batch(SSL *ssl, SOCKET s, const char *sql)
{
    if (!g_timing) { tds_exec(ssl, s, sql); return; }

    LARGE_INTEGER freq, a, b;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&a);
    tds_exec(ssl, s, sql);
    QueryPerformanceCounter(&b);

    double ms = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)freq.QuadPart;
    printf("%sTime: %.3f ms%s\n\n", CLR_DIM, ms, CLR_RESET);
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
 * anything else is buffered and sent to the server as a T-SQL batch on GO. */
static void print_repl_help(void)
{
    printf("\n  %smeta-commands%s %s(everything else is buffered as T-SQL; GO runs it)%s\n",
           CLR_BOLD, CLR_RESET, CLR_DIM, CLR_RESET);
    printf("    %s\\help%s, %s\\?%s        show this help\n",
           CLR_CYAN, CLR_RESET, CLR_CYAN, CLR_RESET);
    printf("    %s\\l%s              list databases\n", CLR_CYAN, CLR_RESET);
    printf("    %s\\dt%s             list tables\n", CLR_CYAN, CLR_RESET);
    printf("    %s\\dv%s             list views\n", CLR_CYAN, CLR_RESET);
    printf("    %s\\dn%s             list schemas\n", CLR_CYAN, CLR_RESET);
    printf("    %s\\d%s %s<table>%s      describe a table's columns\n",
           CLR_CYAN, CLR_RESET, CLR_DIM, CLR_RESET);
    printf("    %s\\timing%s         toggle per-batch elapsed time\n", CLR_CYAN, CLR_RESET);
    printf("    %s\\o%s %s<file>%s       write results to a CSV/TSV file (%s\\o%s alone: back to screen)\n",
           CLR_CYAN, CLR_RESET, CLR_DIM, CLR_RESET, CLR_CYAN, CLR_RESET);
    printf("    %s\\x%s              toggle expanded (one-field-per-line) display\n",
           CLR_CYAN, CLR_RESET);
    printf("    %s\\pager%s          toggle screen-at-a-time paging of long results\n",
           CLR_CYAN, CLR_RESET);
    printf("    %s\\clear%s, %s\\cls%s    clear the screen\n",
           CLR_CYAN, CLR_RESET, CLR_CYAN, CLR_RESET);
    printf("    %s\\exit%s, %s\\q%s       leave tdsh  (or Ctrl+Z then Enter)\n\n",
           CLR_CYAN, CLR_RESET, CLR_CYAN, CLR_RESET);
}

/* Copies src into dst, doubling every single-quote so the value is safe to embed
 * inside a T-SQL string literal. dst is always null-terminated. */
static void sql_escape(const char *src, char *dst, int cap)
{
    int j = 0;
    for (const char *p = src; *p && j < cap - 2; p++) {
        if (*p == '\'') dst[j++] = '\'';
        dst[j++] = *p;
    }
    dst[j] = '\0';
}

enum { META_HANDLED, META_QUIT };

/* Parses and runs a '\'-prefixed meta-command. Returns META_QUIT to end the REPL,
 * META_HANDLED otherwise. Splits line into the command word and a trimmed argument
 * so commands like `\d dbo.Users` and `\o out.csv` work. */
static int handle_meta(SSL *ssl, SOCKET s, char *line)
{
    /* command word = up to the first whitespace */
    char *sp = line;
    while (*sp && !isspace((unsigned char)*sp)) sp++;
    char cmd[32];
    int cl = (int)(sp - line);
    if (cl >= (int)sizeof cmd) cl = sizeof cmd - 1;
    memcpy(cmd, line, cl); cmd[cl] = '\0';

    /* argument = rest, leading and trailing whitespace trimmed */
    while (*sp && isspace((unsigned char)*sp)) sp++;
    char *arg = sp;
    int al = (int)strlen(arg);
    while (al > 0 && isspace((unsigned char)arg[al - 1])) arg[--al] = '\0';

    if (strcmp(cmd, "\\exit") == 0 || strcmp(cmd, "\\q") == 0) return META_QUIT;

    if (strcmp(cmd, "\\help") == 0 || strcmp(cmd, "\\?") == 0) {
        print_repl_help();
    } else if (strcmp(cmd, "\\x") == 0) {
        g_expanded = !g_expanded;
        printf("  %sexpanded display %s%s\n\n", CLR_DIM,
               g_expanded ? "on" : "off (auto)", CLR_RESET);
    } else if (strcmp(cmd, "\\pager") == 0) {
        g_pager = !g_pager;
        printf("  %spager %s%s\n\n", CLR_DIM, g_pager ? "on" : "off", CLR_RESET);
    } else if (strcmp(cmd, "\\timing") == 0) {
        g_timing = !g_timing;
        printf("  %stiming %s%s\n\n", CLR_DIM, g_timing ? "on" : "off", CLR_RESET);
    } else if (strcmp(cmd, "\\clear") == 0 || strcmp(cmd, "\\cls") == 0) {
        clear_screen();
    } else if (strcmp(cmd, "\\l") == 0) {
        run_batch(ssl, s,
            "SELECT name, database_id, create_date FROM sys.databases ORDER BY name");
    } else if (strcmp(cmd, "\\dt") == 0 || (strcmp(cmd, "\\d") == 0 && arg[0] == '\0')) {
        run_batch(ssl, s,
            "SELECT s.name AS [schema], t.name AS [table] "
            "FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id "
            "ORDER BY 1, 2");
    } else if (strcmp(cmd, "\\dv") == 0) {
        run_batch(ssl, s,
            "SELECT s.name AS [schema], v.name AS [view] "
            "FROM sys.views v JOIN sys.schemas s ON s.schema_id = v.schema_id "
            "ORDER BY 1, 2");
    } else if (strcmp(cmd, "\\dn") == 0) {
        run_batch(ssl, s,
            "SELECT name AS [schema], schema_id FROM sys.schemas ORDER BY name");
    } else if (strcmp(cmd, "\\d") == 0) {
        char esc[512], sql[1200];
        sql_escape(arg, esc, sizeof esc);
        snprintf(sql, sizeof sql,
            "SELECT c.name AS [column], ty.name AS [type], c.max_length, "
            "c.precision, c.scale, c.is_nullable "
            "FROM sys.columns c "
            "JOIN sys.types ty ON ty.user_type_id = c.user_type_id "
            "WHERE c.object_id = OBJECT_ID('%s') ORDER BY c.column_id", esc);
        run_batch(ssl, s, sql);
    } else if (strcmp(cmd, "\\o") == 0) {
        if (g_out) { fclose(g_out); g_out = NULL; }
        if (arg[0] == '\0') {
            printf("  %soutput → terminal%s\n\n", CLR_DIM, CLR_RESET);
        } else {
            g_out = fopen(arg, "w");
            if (!g_out) {
                printf("  %scannot open %s%s%s\n\n", CLR_RED, CLR_RESET, arg, CLR_RESET);
            } else {
                int n = (int)strlen(arg);
                g_out_delim = (n >= 4 && _stricmp(arg + n - 4, ".tsv") == 0) ? '\t' : ',';
                printf("  %swriting results to %s%s%s %s(%s)%s\n\n",
                       CLR_DIM, CLR_RESET, arg, CLR_DIM,
                       CLR_DIM, g_out_delim == '\t' ? "TSV" : "CSV", CLR_RESET);
            }
        }
    } else {
        printf("  %sunknown command %s%s%s — try %s\\help%s\n\n",
               CLR_DIM, CLR_RESET, cmd, CLR_DIM, CLR_CYAN, CLR_RESET);
    }
    return META_HANDLED;
}

/* ============================================================
 *  Line editor: history + in-line cursor editing over _getch
 * ============================================================ */

static char *g_hist[HIST_MAX];
static int   g_hist_count = 0;

/* Appends a line to the history ring (skipping empties and immediate duplicates). */
static void hist_push(const char *line)
{
    if (!line || !line[0]) return;
    if (g_hist_count > 0 && strcmp(g_hist[g_hist_count - 1], line) == 0) return;

    char *copy = _strdup(line);
    if (!copy) return;
    if (g_hist_count == HIST_MAX) {                 /* full: drop the oldest */
        free(g_hist[0]);
        memmove(g_hist, g_hist + 1, (HIST_MAX - 1) * sizeof(char *));
        g_hist_count--;
    }
    g_hist[g_hist_count++] = copy;
}

/* Repaint the edited line: carriage-return, reprint prompt + buffer, clear to end
 * of line, then park the cursor at `pos`. Relies on VT sequences. */
static void le_redraw(const char *prompt, const char *buf, int len, int pos)
{
    fputs("\r", stdout);
    fputs(prompt, stdout);
    fwrite(buf, 1, (size_t)len, stdout);
    fputs("\x1b[K", stdout);                         /* erase to end of line */
    if (pos < len) printf("\x1b[%dD", len - pos);    /* move cursor left to pos */
    fflush(stdout);
}

/* Reads one line with history (Up/Down), cursor movement (Left/Right/Home/End),
 * Backspace/Delete, and Ctrl+C (cancel) / Ctrl+Z (EOF). Returns the line length,
 * or -1 on EOF. Falls back to fgets when stdout is not a VT console (redirected
 * input, legacy console), so scripting still works. */
static int read_line_edit(const char *prompt, char *buf, int cap)
{
    if (!is_console() || !g_vt) {                    /* fallback: plain fgets */
        fputs(prompt, stdout); fflush(stdout);
        if (!fgets(buf, cap, stdin)) return -1;
        int n = (int)strlen(buf);
        while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
        return n;
    }

    int len = 0, pos = 0;
    buf[0] = '\0';
    int hidx = g_hist_count;                          /* == count means "current line" */
    char saved[LINE_MAX];
    saved[0] = '\0';

    le_redraw(prompt, buf, len, pos);
    for (;;) {
        int ch = _getch();

        if (ch == '\r' || ch == '\n') {               /* Enter — submit */
            fputs("\r\n", stdout); fflush(stdout);
            buf[len] = '\0';
            return len;
        }
        if (ch == 26) { fputs("\r\n", stdout); return -1; }   /* Ctrl+Z — EOF */
        if (ch == 3)  { buf[0] = '\0'; fputs("^C\r\n", stdout); return 0; }  /* Ctrl+C */

        if (ch == 0 || ch == 0xE0) {                  /* extended key: read the code */
            int k = _getch();
            switch (k) {
            case 0x4B: if (pos > 0) pos--; break;                 /* Left  */
            case 0x4D: if (pos < len) pos++; break;               /* Right */
            case 0x47: pos = 0; break;                            /* Home  */
            case 0x4F: pos = len; break;                          /* End   */
            case 0x53:                                            /* Delete */
                if (pos < len) { memmove(buf + pos, buf + pos + 1, len - pos - 1);
                                 len--; buf[len] = '\0'; }
                break;
            case 0x48:                                            /* Up — older */
                if (hidx > 0) {
                    if (hidx == g_hist_count) {
                        strncpy(saved, buf, sizeof saved - 1); saved[sizeof saved - 1] = '\0';
                    }
                    hidx--;
                    strncpy(buf, g_hist[hidx], cap - 1); buf[cap - 1] = '\0';
                    len = (int)strlen(buf); pos = len;
                }
                break;
            case 0x50:                                            /* Down — newer */
                if (hidx < g_hist_count) {
                    hidx++;
                    const char *src = (hidx == g_hist_count) ? saved : g_hist[hidx];
                    strncpy(buf, src, cap - 1); buf[cap - 1] = '\0';
                    len = (int)strlen(buf); pos = len;
                }
                break;
            default: break;
            }
            le_redraw(prompt, buf, len, pos);
            continue;
        }

        if (ch == '\b' || ch == 127) {                /* Backspace */
            if (pos > 0) {
                memmove(buf + pos - 1, buf + pos, len - pos);
                pos--; len--; buf[len] = '\0';
                le_redraw(prompt, buf, len, pos);
            }
            continue;
        }
        if (ch < 32) continue;                        /* ignore other control chars */

        if (len < cap - 1) {                          /* insert a printable char at pos */
            memmove(buf + pos + 1, buf + pos, len - pos);
            buf[pos] = (char)ch;
            pos++; len++; buf[len] = '\0';
            le_redraw(prompt, buf, len, pos);
        }
    }
}

/* True when a physical line is a standalone batch terminator: optional leading
 * whitespace, "GO" (case-insensitive), then only whitespace. */
static int is_go_line(const char *line)
{
    const char *p = line;
    while (*p && isspace((unsigned char)*p)) p++;
    if (tolower((unsigned char)p[0]) != 'g' || tolower((unsigned char)p[1]) != 'o')
        return 0;
    p += 2;
    while (*p && isspace((unsigned char)*p)) p++;
    return *p == '\0';
}

/* Interactive read-eval-print loop. Physical lines are accumulated into a batch
 * and sent when a standalone GO is entered; '\'-prefixed meta-commands (only at
 * the start of a fresh batch) are handled locally. */
void run_repl(SSL *ssl, SOCKET s)
{
    char line[LINE_MAX];
    char batch[BATCH_MAX];
    int  blen = 0;
    batch[0] = '\0';

    /* let queries take their time; login used a short recv timeout */
    DWORD timeout = 60000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    printf("\n  %s%stdsh%s %sinteractive%s — type T-SQL, %sGO%s to run, "
           "%s\\help%s for commands.\n\n",
           CLR_BOLD, CLR_CYAN, CLR_RESET, CLR_DIM, CLR_RESET,
           CLR_BOLD, CLR_RESET, CLR_CYAN, CLR_RESET);

    for (;;) {
        char prompt[80];
        if (blen == 0)
            snprintf(prompt, sizeof prompt, "%s%stdsh>%s ", CLR_BOLD, CLR_GREEN, CLR_RESET);
        else
            snprintf(prompt, sizeof prompt, "%s  ...>%s ", CLR_DIM, CLR_RESET);

        int r = read_line_edit(prompt, line, sizeof line);
        if (r < 0) break;                             /* EOF (Ctrl+Z) */

        if (r > 0) hist_push(line);

        /* meta-commands only make sense at the start of a fresh batch */
        if (blen == 0 && line[0] == '\\') {
            if (handle_meta(ssl, s, line) == META_QUIT) break;
            continue;
        }

        if (is_go_line(line)) {                       /* run the accumulated batch */
            if (blen > 0) { run_batch(ssl, s, batch); blen = 0; batch[0] = '\0'; }
            continue;
        }

        if (blen == 0 && r == 0) continue;            /* blank line, nothing buffered */

        int add = (int)strlen(line);
        if (blen + add + 2 >= (int)sizeof batch) {    /* would overflow — drop it */
            printf("  %sbatch too large — cleared%s\n\n", CLR_RED, CLR_RESET);
            blen = 0; batch[0] = '\0';
            continue;
        }
        memcpy(batch + blen, line, add); blen += add;
        batch[blen++] = '\n'; batch[blen] = '\0';     /* keep line breaks for the server */
    }

    if (g_out) { fclose(g_out); g_out = NULL; }       /* flush any open \o file */
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
void prompt_connection(char *host, char *port, char *user,
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
