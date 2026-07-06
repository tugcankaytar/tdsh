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

/* Emits the whole result set to f as delimited text (used when \o is active).
 * Header row, then data rows; SQL NULL becomes an empty field. */
static void render_csv(const Table *t, FILE *f, char delim)
{
    for (int c = 0; c < t->ncols; c++) {
        if (c) fputc(delim, f);
        csv_field(f, t->cols[c].name, delim);
    }
    fputc('\n', f);
    for (int r = 0; r < t->nrows; r++) {
        for (int c = 0; c < t->ncols; c++) {
            if (c) fputc(delim, f);
            const char *v = t->rows[r][c] ? t->rows[r][c] : "";
            if (cell_is_null(v)) v = "";                 /* NULL -> empty field */
            csv_field(f, v, delim);
        }
        fputc('\n', f);
    }
    fflush(f);
    printf("%s(%d row%s → file)%s\n\n", CLR_DIM, t->nrows, t->nrows == 1 ? "" : "s", CLR_RESET);
}

static void table_render(Table *t)
{
    if (t->ncols == 0) return;

    if (g_out) { render_csv(t, g_out, g_out_delim); return; }  /* \o export path */

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
void parse_result_stream(const unsigned char *tok, int len)
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
