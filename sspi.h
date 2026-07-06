/*
 * sspi.h — thin wrapper over the Windows SSPI Negotiate/NTLM package, used for
 * integrated (Windows) authentication to SQL Server. Windows-only; on other
 * platforms sspi_supported() returns 0 and the calls fail cleanly.
 */

#ifndef SSPI_H
#define SSPI_H

typedef struct SspiState SspiState;   /* opaque */

int         sspi_supported(void);     /* 1 on Windows with SSPI available */
SspiState  *sspi_new(void);
void        sspi_free(SspiState *st);

/* Produce the first outbound token (no server input yet). Returns 0 on success;
 * *tok is malloc'd (caller frees) and *toklen set. spn may be NULL. */
int sspi_first(SspiState *st, const char *spn, unsigned char **tok, int *toklen);

/* Feed the server's challenge and produce the next outbound token. Sets *done
 * when the context is complete. *tok may be NULL/0 when there is nothing more to
 * send. Returns 0 on success. */
int sspi_next(SspiState *st, const char *spn, const unsigned char *in, int inlen,
              unsigned char **tok, int *toklen, int *done);

#endif /* SSPI_H */
