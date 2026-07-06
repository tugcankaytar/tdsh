#include "platform.h"
#include "sspi.h"

#ifdef _WIN32

#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>

struct SspiState {
    CredHandle cred;
    CtxtHandle ctx;
    int have_cred, have_ctx;
};

int sspi_supported(void) { return 1; }

SspiState *sspi_new(void)
{
    SspiState *st = calloc(1, sizeof *st);
    return st;
}

void sspi_free(SspiState *st)
{
    if (!st) return;
    if (st->have_ctx)  DeleteSecurityContext(&st->ctx);
    if (st->have_cred) FreeCredentialsHandle(&st->cred);
    free(st);
}

/* Common flags: let SSPI allocate the output buffer, request a connection-style
 * context with confidentiality (matches what SQL Server negotiates). */
#define ISC_FLAGS (ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_CONNECTION)

static int copy_out(SecBuffer *ob, unsigned char **tok, int *toklen)
{
    *toklen = (int)ob->cbBuffer;
    if (ob->cbBuffer && ob->pvBuffer) {
        *tok = malloc(ob->cbBuffer);
        if (!*tok) { FreeContextBuffer(ob->pvBuffer); return -1; }
        memcpy(*tok, ob->pvBuffer, ob->cbBuffer);
    } else {
        *tok = NULL;
    }
    if (ob->pvBuffer) FreeContextBuffer(ob->pvBuffer);
    return 0;
}

int sspi_first(SspiState *st, const char *spn, unsigned char **tok, int *toklen)
{
    TimeStamp ts;
    SECURITY_STATUS ss = AcquireCredentialsHandleA(
        NULL, "Negotiate", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &st->cred, &ts);
    if (ss != SEC_E_OK) { printf("AcquireCredentialsHandle failed: 0x%lx\n", (unsigned long)ss); return -1; }
    st->have_cred = 1;

    SecBuffer ob = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc od = { SECBUFFER_VERSION, 1, &ob };
    ULONG attrs = 0; TimeStamp expiry;

    ss = InitializeSecurityContextA(
        &st->cred, NULL, (SEC_CHAR *)spn, ISC_FLAGS, 0, SECURITY_NATIVE_DREP,
        NULL, 0, &st->ctx, &od, &attrs, &expiry);
    if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED) {
        printf("InitializeSecurityContext failed: 0x%lx\n", (unsigned long)ss);
        return -1;
    }
    st->have_ctx = 1;
    return copy_out(&ob, tok, toklen);
}

int sspi_next(SspiState *st, const char *spn, const unsigned char *in, int inlen,
              unsigned char **tok, int *toklen, int *done)
{
    SecBuffer ib = { (unsigned long)inlen, SECBUFFER_TOKEN, (void *)in };
    SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib };
    SecBuffer ob = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc od = { SECBUFFER_VERSION, 1, &ob };
    ULONG attrs = 0; TimeStamp expiry;

    SECURITY_STATUS ss = InitializeSecurityContextA(
        &st->cred, &st->ctx, (SEC_CHAR *)spn, ISC_FLAGS, 0, SECURITY_NATIVE_DREP,
        &id, 0, &st->ctx, &od, &attrs, &expiry);
    if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED) {
        printf("InitializeSecurityContext(step) failed: 0x%lx\n", (unsigned long)ss);
        return -1;
    }
    *done = (ss == SEC_E_OK);
    return copy_out(&ob, tok, toklen);
}

#else  /* ---- non-Windows: integrated auth unsupported ---- */

int         sspi_supported(void) { return 0; }
SspiState  *sspi_new(void) { return NULL; }
void        sspi_free(SspiState *st) { (void)st; }
int sspi_first(SspiState *st, const char *spn, unsigned char **tok, int *toklen)
{ (void)st; (void)spn; (void)tok; (void)toklen; return -1; }
int sspi_next(SspiState *st, const char *spn, const unsigned char *in, int inlen,
              unsigned char **tok, int *toklen, int *done)
{ (void)st; (void)spn; (void)in; (void)inlen; (void)tok; (void)toklen; (void)done; return -1; }

#endif
