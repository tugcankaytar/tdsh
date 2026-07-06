#include "tdsh.h"

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
void utf8_from_utf16le(const unsigned char *v, int nbytes, char *out, int outcap)
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
int read_cell(const Column *c, const unsigned char *p, int avail,
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
int parse_type_info(const unsigned char *p, int avail, Column *col)
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
int read_bvarchar_name(const unsigned char *p, int avail, char *name, int namecap)
{
    if (avail < 1) return -1;
    int nchars = p[0];
    if (avail < 1 + nchars * 2) return -1;
    utf8_from_utf16le(p + 1, nchars * 2, name, namecap);
    return 1 + nchars * 2;
}
