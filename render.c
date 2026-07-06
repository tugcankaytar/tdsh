#include "tdsh.h"

/* Box-drawing glyphs for result tables. */
typedef struct {
    const char *h, *v;
    const char *tl, *tm, *tr;   /* top    row: corners/junctions */
    const char *ml, *mm, *mr;   /* middle sep */
    const char *bl, *bm, *br;   /* bottom row */
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

/* --- rendering helpers --- */

static void print_repeat(char ch, int n) { for (int i = 0; i < n; i++) putchar(ch); }

/* Repeat a (possibly multi-byte) glyph string n times — used for box borders. */
static void print_repeat_s(const char *s, int n) { for (int i = 0; i < n; i++) fputs(s, stdout); }

/* Decodes one UTF-8 sequence at s into *cp and returns its byte length (>=1).
 * The short-circuit continuation checks stop at a null or a bad byte, so a
 * truncated sequence at end-of-string never reads past the terminator. */
static int utf8_decode(const unsigned char *s, unsigned int *cp)
{
    unsigned char c = s[0];
    if (c < 0x80) { *cp = c; return 1; }
    if ((c & 0xE0) == 0xC0 && (s[1] & 0xC0) == 0x80) {
        *cp = ((c & 0x1Fu) << 6) | (s[1] & 0x3Fu); return 2;
    }
    if ((c & 0xF0) == 0xE0 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80) {
        *cp = ((c & 0x0Fu) << 12) | ((s[1] & 0x3Fu) << 6) | (s[2] & 0x3Fu); return 3;
    }
    if ((c & 0xF8) == 0xF0 && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80) {
        *cp = ((c & 0x07u) << 18) | ((s[1] & 0x3Fu) << 12) | ((s[2] & 0x3Fu) << 6) | (s[3] & 0x3Fu);
        return 4;
    }
    *cp = c; return 1;                               /* invalid lead byte: width-1 */
}

/* Terminal display width of one code point: 0 for zero-width (combining marks,
 * joiners, variation selectors), 2 for East-Asian wide / fullwidth / most emoji,
 * 1 otherwise. A compact wcwidth-style table — enough to keep CJK from skewing
 * column alignment without pulling in a full Unicode database. */
static int cp_width(unsigned int cp)
{
    if (cp == 0) return 0;
    if ((cp >= 0x0300 && cp <= 0x036F) ||            /* combining diacritics */
        (cp >= 0x200B && cp <= 0x200F) ||            /* zero-width space/joiners/marks */
        (cp >= 0x202A && cp <= 0x202E) ||            /* bidi controls */
        (cp >= 0xFE00 && cp <= 0xFE0F) ||            /* variation selectors */
        (cp >= 0xFE20 && cp <= 0xFE2F) ||            /* combining half marks */
        cp == 0xFEFF)                                /* BOM / ZWNBSP */
        return 0;
    if ((cp >= 0x1100 && cp <= 0x115F) ||            /* Hangul Jamo */
        (cp >= 0x2E80 && cp <= 0x303E) ||            /* CJK radicals … symbols */
        (cp >= 0x3041 && cp <= 0x33FF) ||            /* Kana … CJK compat */
        (cp >= 0x3400 && cp <= 0x4DBF) ||            /* CJK Ext A */
        (cp >= 0x4E00 && cp <= 0x9FFF) ||            /* CJK Unified */
        (cp >= 0xA000 && cp <= 0xA4CF) ||            /* Yi */
        (cp >= 0xAC00 && cp <= 0xD7A3) ||            /* Hangul syllables */
        (cp >= 0xF900 && cp <= 0xFAFF) ||            /* CJK compat ideographs */
        (cp >= 0xFE10 && cp <= 0xFE19) ||            /* vertical forms */
        (cp >= 0xFE30 && cp <= 0xFE6F) ||            /* CJK compat forms */
        (cp >= 0xFF00 && cp <= 0xFF60) ||            /* fullwidth forms */
        (cp >= 0xFFE0 && cp <= 0xFFE6) ||            /* fullwidth signs */
        (cp >= 0x1F300 && cp <= 0x1FAFF) ||          /* symbols & emoji */
        (cp >= 0x20000 && cp <= 0x3FFFD))            /* CJK Ext B+ */
        return 2;
    return 1;
}

/* Display width of a whole UTF-8 string, in terminal columns. */
static int utf8_ncols(const char *s)
{
    int n = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p) { unsigned int cp; int len = utf8_decode(p, &cp); n += cp_width(cp); p += len; }
    return n;
}

/* Print s truncated to at most `width` display columns (ellipsis if clipped),
 * with no padding. Returns the number of display columns actually written. */
static int print_clip(const char *s, int width)
{
    int dw = utf8_ncols(s);
    if (dw <= width) { fputs(s, stdout); return dw; }

    int budget = width > 0 ? width - 1 : 0;          /* leave 1 column for the ellipsis */
    const unsigned char *p = (const unsigned char *)s;
    int used = 0;
    while (*p) {
        unsigned int cp; int len = utf8_decode(p, &cp);
        int w = cp_width(cp);
        if (used + w > budget) break;                /* next glyph would overflow */
        used += w; p += len;
    }
    fwrite(s, 1, (size_t)((const char *)p - s), stdout);
    fputs("\xE2\x80\xA6", stdout);                   /* … (1 column) */
    return used + 1;
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
int is_console(void)
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

/* ---- Row streaming -------------------------------------------------------
 * Instead of buffering every row's formatted strings, we walk the (already
 * in-memory) token buffer and format one row at a time into a reused scratch
 * array. Rendering a result set makes two passes: one to measure column widths,
 * one to print — so memory stays O(ncols), not O(nrows × ncols), and there is
 * no fixed row cap. */

/* Formats one ROW/NBCROW body (p is just after the type byte) into cells[], one
 * buffer of CELL_MAX per column. nbc selects the null-bitmap-compressed layout.
 * Returns bytes consumed, or -1 on a framing error. */
static int read_row_body(const Column *cols, int ncols, int nbc,
                         const unsigned char *p, int avail, char (*cells)[CELL_MAX])
{
    int i = 0;
    const unsigned char *bitmap = NULL;
    if (nbc) {
        int nbytes = (ncols + 7) / 8;
        if (avail < nbytes) return -1;
        bitmap = p; i = nbytes;
    }
    for (int c = 0; c < ncols; c++) {
        if (nbc && (bitmap[c / 8] & (1 << (c % 8)))) { memcpy(cells[c], "NULL", 5); continue; }
        int used = 0;
        if (read_cell(&cols[c], p + i, avail - i, cells[c], CELL_MAX, &used) < 0) return -1;
        i += used;
    }
    return i;
}

typedef struct {
    const unsigned char *tok;
    int pos, len;
    const Column *cols;
    int ncols;
    char (*cells)[CELL_MAX];
    int error;
} RowStream;

/* Advances to the next ROW/NBCROW, filling rs->cells. Returns 1 on a row, or 0
 * at the end of the result set (rs->pos left at the terminating non-row token);
 * on a framing error returns 0 with rs->error set. */
static int rowstream_next(RowStream *rs)
{
    if (rs->pos >= rs->len) return 0;
    uint8_t tp = rs->tok[rs->pos];
    if (tp != 0xD1 && tp != 0xD2) return 0;
    int used = read_row_body(rs->cols, rs->ncols, tp == 0xD2,
                             rs->tok + rs->pos + 1, rs->len - rs->pos - 1, rs->cells);
    if (used < 0) { rs->error = 1; return 0; }
    rs->pos += 1 + used;
    return 1;
}

/* Classic grid layout in a coloured box: header, separator, streamed rows,
 * footer. w[] holds each column's display width; rows are paged a screenful at
 * a time and pulled from `rs` one at a time. */
static void render_normal(Table *t, const int *w, RowStream *rs)
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
    while (rowstream_next(rs)) {                       /* data rows, streamed */
        render_bar(&b);
        for (int c = 0; c < t->ncols; c++) {
            const char *cell = rs->cells[c];
            int nul = cell_is_null(cell);
            putchar(' ');
            if (nul) fputs(CLR_DIM, stdout);
            print_padded(cell, w[c], col_is_numeric(t->cols[c].type));
            if (nul) fputs(CLR_RESET, stdout);
            putchar(' ');
            render_bar(&b);
        }
        putchar('\n');
        r++;
        if (!pager_step(&pg)) break;                  /* user quit the pager */
    }

    render_rule(t, w, &b, b.bl, b.bm, b.br);         /* └─┴─┘ */
    print_rowcount(t, r, pg.quit);
}

/* Expanded layout (psql's \x): one "column | value" line per field, grouped
 * per record. Used for tables too wide to fit the terminal as a grid. Paged by
 * output line so very tall records don't scroll off unseen. */
static void render_expanded(Table *t, RowStream *rs)
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
    while (!pg.quit && rowstream_next(rs)) {
        char label[48];
        int n = snprintf(label, sizeof label, "[ RECORD %d ]", shown + 1);
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
            const char *v = rs->cells[c];
            if (cell_is_null(v)) fputs(CLR_DIM, stdout);
            print_clip(v, valw);                     /* no trailing pad */
            if (cell_is_null(v)) fputs(CLR_RESET, stdout);
            putchar('\n');
            if (!pager_step(&pg)) break;
        }
        shown++;
    }
    print_rowcount(t, shown, pg.quit);
}

/* Writes one CSV/TSV field, quoting per RFC 4180 when it contains the delimiter,
 * a double-quote, or a newline (doubling any embedded quote). */
static void csv_field(FILE *f, const char *s, char delim)
{
    int needq = 0;
    for (const char *p = s; *p; p++)
        if (*p == delim || *p == '"' || *p == '\n' || *p == '\r') { needq = 1; break; }
    if (!needq) { fputs(s, f); return; }
    fputc('"', f);
    for (const char *p = s; *p; p++) { if (*p == '"') fputc('"', f); fputc(*p, f); }
    fputc('"', f);
}

/* Streams the result set to f as delimited text (used when \o is active).
 * Header row, then data rows pulled from rs; SQL NULL becomes an empty field. */
static void render_csv(const Table *t, FILE *f, char delim, RowStream *rs)
{
    for (int c = 0; c < t->ncols; c++) {
        if (c) fputc(delim, f);
        csv_field(f, t->cols[c].name, delim);
    }
    fputc('\n', f);
    int r = 0;
    while (rowstream_next(rs)) {
        for (int c = 0; c < t->ncols; c++) {
            if (c) fputc(delim, f);
            const char *v = rs->cells[c];
            if (cell_is_null(v)) v = "";                 /* NULL -> empty field */
            csv_field(f, v, delim);
        }
        fputc('\n', f);
        r++;
    }
    fflush(f);
    printf("%s(%d row%s → file)%s\n\n", CLR_DIM, r, r == 1 ? "" : "s", CLR_RESET);
}

/* Renders one result set by streaming its rows over the token buffer starting at
 * rows_start: a measuring pass computes column widths and the row count, then a
 * printing pass renders (grid or expanded, or CSV to \o). Returns the buffer
 * position just past the last row — the terminating (non-row) token. */
static int render_stream(Table *t, const unsigned char *tok, int rows_start, int len,
                         char (*cells)[CELL_MAX])
{
    if (t->ncols == 0) return rows_start;

    /* CSV export needs no widths — a single streaming pass. */
    if (g_out) {
        RowStream rs = { tok, rows_start, len, t->cols, t->ncols, cells, 0 };
        render_csv(t, g_out, g_out_delim, &rs);
        if (rs.error) printf("%s(row parse error — output truncated)%s\n", CLR_DIM, CLR_RESET);
        return rs.pos;
    }

    /* Pass 1 — measure each column's display width and count rows. */
    int w[MAX_COLS];
    for (int c = 0; c < t->ncols; c++) {
        int mx = utf8_ncols(t->cols[c].name);
        w[c] = mx < 1 ? 1 : mx;
    }
    RowStream meas = { tok, rows_start, len, t->cols, t->ncols, cells, 0 };
    int nrows = 0;
    while (rowstream_next(&meas)) {
        for (int c = 0; c < t->ncols; c++) {
            int cl = utf8_ncols(cells[c]);
            if (cl > w[c]) w[c] = cl;
        }
        nrows++;
    }
    int rows_end = meas.pos;
    t->nrows = nrows;
    t->truncated = 0;

    /* cap each column, then shrink the widest to fit the terminal */
    long total = 3 * t->ncols + 1;                   /* box borders + separators */
    for (int c = 0; c < t->ncols; c++) {
        if (w[c] > NORMAL_CAP) w[c] = NORMAL_CAP;
        total += w[c];
    }
    int avail = term_width();
    while (total > avail) {
        int wc = -1, wmax = MIN_COL;
        for (int c = 0; c < t->ncols; c++)
            if (w[c] > wmax) { wmax = w[c]; wc = c; }
        if (wc < 0) break;                           /* nothing left to shrink */
        w[wc]--; total--;
    }

    /* Pass 2 — print, streaming the rows again from the same start. */
    RowStream out = { tok, rows_start, len, t->cols, t->ncols, cells, 0 };
    if (g_expanded || total > avail)
        render_expanded(t, &out);
    else
        render_normal(t, w, &out);

    if (meas.error)
        printf("%s(row parse error — result may be incomplete)%s\n", CLR_DIM, CLR_RESET);
    return rows_end;
}

/* Walks a result-set token stream and prints each result set as a table.
 * On COLMETADATA the columns are parsed and the following rows are streamed
 * straight to output (two passes over the buffer, no per-row buffering). Also
 * handles the DONE-family (rows-affected), ERROR (0xAA) and INFO (0xAB). */
void parse_result_stream(const unsigned char *tok, int len)
{
    Table t; memset(&t, 0, sizeof(t));
    int i = 0;
    int any_output = 0;
    int just_rendered = 0;                  /* last statement produced a result grid */

    /* Reusable scratch: one CELL_MAX buffer per column, grown as needed. */
    char (*cells)[CELL_MAX] = NULL;
    int cells_cap = 0;

    while (i < len) {
        uint8_t type = tok[i++];

        if (type == 0x81) {                        /* COLMETADATA */
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
                    free(cells); return;
                }
                i += used;
                int nu = read_bvarchar_name(tok + i, len - i, t.cols[c].name, sizeof(t.cols[c].name));
                if (nu < 0) { t.ncols = c; break; }
                i += nu;
            }
            any_output = 1;

            if (t.ncols > cells_cap) {              /* grow the scratch row */
                free(cells);
                cells = malloc((size_t)t.ncols * CELL_MAX);
                if (!cells) { printf("out of memory\n"); return; }
                cells_cap = t.ncols;
            }

            i = render_stream(&t, tok, i, len, cells);   /* stream this set's rows */
            just_rendered = 1;
        }
        else if (type == 0xFD || type == 0xFE || type == 0xFF) {  /* DONE / DONEPROC / DONEINPROC */
            if (i + 12 <= len) {
                int status = tok[i] | (tok[i + 1] << 8);          /* Status(2) */
                unsigned long long rc = read_uint_le(tok + i + 4, 8);  /* RowCount(8) */
                if ((status & 0x10) && !just_rendered) {  /* DONE_COUNT on a non-result statement */
                    printf("%s(%llu row%s affected)%s\n\n",
                           CLR_DIM, rc, rc == 1 ? "" : "s", CLR_RESET);
                    any_output = 1;
                }
            }
            just_rendered = 0;
            i += 12;                                /* Status(2) + CurCmd(2) + RowCount(8) */
        }
        else if (type == 0x79) {                   /* RETURNSTATUS */
            i += 4;
        }
        else if ((type & 0x30) == 0x20) {          /* variable-length token (USHORT length) */
            if (i + 2 > len) break;
            int tl = tok[i] | (tok[i + 1] << 8); i += 2;
            if (tl > len - i) tl = len - i;
            if (type == 0xAA) print_error_token(tok + i, tl);        /* ERROR — show message */
            else if (type == 0xAB) { print_info_token(tok + i, tl); any_output = 1; }  /* INFO/PRINT */
            i += tl;
        }
        else {
            printf("(unknown token 0x%02X — stopping)\n", type);
            break;
        }
    }

    if (!any_output) printf("%s(command completed, no result set)%s\n\n", CLR_DIM, CLR_RESET);
    free(cells);
}
