#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "nsh_scripts.h"

/* ============================================================ */
/* Configurazione                                                */
/* ============================================================ */
#define ESP_FOLDER      L"EFI\\EfiStage"
#define ESP_EFI_NAME    L"efi_stage.efi"
#define ESP_SIGNED_NAME L"efi_stage_signed.efi"
#define ESP_ENROLL_DEF  L"EnrollDefaultKeys.efi"
#define ESP_UPDATE_VARS L"UpdateVars.efi"
#define ESP_STARTUP_NSH L"startup.nsh"
#define WIN_STAGE_DIR   L"C:\\ProgramData\\MyApp"
#define WIN_STAGE_NAME  L"win_stage.exe"
#define BCD_DESC        L"EfiStage"
#define TASK_NAME       L"MyAppStage2"
#define KEY_DIR         L"C:\\ProgramData\\MyApp\\keys"
#define KEY_PRIV        L"C:\\ProgramData\\MyApp\\keys\\MOK.key"
#define KEY_CERT        L"C:\\ProgramData\\MyApp\\keys\\MOK.crt"
#define KEY_DER         L"C:\\ProgramData\\MyApp\\keys\\MOK.der"

/* ============================================================ */
/* Utility Windows                                               */
/* ============================================================ */
static void die(const wchar_t *Msg) {
    fwprintf(stderr, L"[install] ERRORE: %ls (GetLastError=%lu)\n", Msg, GetLastError());
    ExitProcess(1);
}

static bool is_admin(void) {
    BOOL admin = FALSE; PSID grp = NULL;
    SID_IDENTIFIER_AUTHORITY Nt = { SECURITY_NT_AUTHORITY };
    if (AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &grp)) {
        CheckTokenMembership(NULL, grp, &admin); FreeSid(grp);
    }
    return admin == TRUE;
}

static DWORD run_and_wait(const wchar_t *CmdLine) {
    wchar_t buf[2048]; wcsncpy(buf, CmdLine, 2047); buf[2047] = 0;
    STARTUPINFOW si = {0}; PROCESS_INFORMATION pi = {0}; si.cb = sizeof(si);
    if (!CreateProcessW(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) return (DWORD)-1;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec = (DWORD)-1; GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return ec;
}

static BOOL run_capture(const wchar_t *CmdLine, char *Out, DWORD OutCch) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return FALSE;
    STARTUPINFOW si = {0}; PROCESS_INFORMATION pi = {0}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = wr; si.hStdError = wr; si.wShowWindow = SW_HIDE;
    wchar_t buf[2048]; wcsncpy(buf, CmdLine, 2047); buf[2047] = 0;
    if (!CreateProcessW(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr); return FALSE;
    }
    CloseHandle(wr);
    DWORD total = 0, got = 0;
    while (total < OutCch - 1 &&
           ReadFile(rd, Out + total, OutCch - 1 - total, &got, NULL) && got > 0)
        total += got;
    Out[total] = 0; CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return TRUE;
}

static BOOL find_esp(wchar_t *OutRoot, size_t OutCch) {
    wchar_t vol[MAX_PATH];
    HANDLE h = FindFirstVolumeW(vol, MAX_PATH);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    BOOL found = FALSE;
    do {
        wchar_t probe[MAX_PATH];
        _snwprintf(probe, MAX_PATH, L"%sEFI\\Microsoft\\Boot\\bootmgfw.efi", vol);
        probe[MAX_PATH-1] = 0;
        if (GetFileAttributesW(probe) != INVALID_FILE_ATTRIBUTES) {
            wcsncpy(OutRoot, vol, OutCch - 1); OutRoot[OutCch-1] = 0;
            found = TRUE; break;
        }
    } while (FindNextVolumeW(h, vol, MAX_PATH));
    FindVolumeClose(h); return found;
}

static void ensure_dir(const wchar_t *Path) {
    if (!CreateDirectoryW(Path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        die(L"CreateDirectory");
}

static void copy_file_or_die(const wchar_t *Src, const wchar_t *Dst) {
    if (!CopyFileW(Src, Dst, FALSE)) die(L"CopyFile");
}

static BOOL write_bin(const wchar_t *Path, const void *Data, size_t Len) {
    HANDLE h = CreateFileW(Path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, Data, (DWORD)Len, &wr, NULL) && wr == Len;
    CloseHandle(h);
    return ok;
}

static unsigned char *read_file(const wchar_t *Path, size_t *OutLen) {
    HANDLE h = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return NULL; }
    *OutLen = (size_t)sz.QuadPart;
    unsigned char *buf = malloc(*OutLen + 1);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD rd = 0;
    if (!ReadFile(h, buf, (DWORD)*OutLen, &rd, NULL) || rd != *OutLen) {
        free(buf); CloseHandle(h); return NULL;
    }
    CloseHandle(h); buf[*OutLen] = 0; return buf;
}

/* ============================================================ */
/* Generazione chiavi MOK (RSA 2048 + X.509 self-signed)         */
/* ============================================================ */
static BOOL generate_keys(void) {
    if (GetFileAttributesW(KEY_PRIV) != INVALID_FILE_ATTRIBUTES &&
        GetFileAttributesW(KEY_CERT) != INVALID_FILE_ATTRIBUTES &&
        GetFileAttributesW(KEY_DER)  != INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[install] chiavi MOK già presenti in %ls\n", KEY_DIR);
        return TRUE;
    }
    ensure_dir(KEY_DIR);

    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    if (!pkey) { fwprintf(stderr, L"[install] EVP_RSA_gen fallito\n"); return FALSE; }

    FILE *fp = _wfopen(KEY_PRIV, L"wb");
    if (!fp) { EVP_PKEY_free(pkey); return FALSE; }
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

    X509 *x509 = X509_new();
    if (!x509) { EVP_PKEY_free(pkey); return FALSE; }
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 60L * 60 * 24 * 3650);
    X509_set_pubkey(x509, pkey);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"My EFI Stage MOK", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        X509_free(x509); EVP_PKEY_free(pkey); return FALSE;
    }

    fp = _wfopen(KEY_CERT, L"wb");
    if (!fp) { X509_free(x509); EVP_PKEY_free(pkey); return FALSE; }
    PEM_write_X509(fp, x509);
    fclose(fp);

    fp = _wfopen(KEY_DER, L"wb");
    if (!fp) { X509_free(x509); EVP_PKEY_free(pkey); return FALSE; }
    i2d_X509_fp(fp, x509);
    fclose(fp);

    X509_free(x509); EVP_PKEY_free(pkey);
    wprintf(L"[install] chiavi MOK generate in %ls\n", KEY_DIR);
    return TRUE;
}

/* ============================================================ */
/* DER encoding helpers                                          */
/* ============================================================ */
typedef struct { unsigned char *b; size_t n; size_t c; } der_t;

static void der_init(der_t *d, size_t cap) {
    d->b = malloc(cap); d->n = 0; d->c = cap;
}
static void der_free(der_t *d) { free(d->b); d->b = NULL; d->n = 0; d->c = 0; }
static void der_reserve(der_t *d, size_t need) {
    if (d->n + need > d->c) {
        while (d->n + need > d->c) d->c = d->c * 2 + 64;
        d->b = realloc(d->b, d->c);
    }
}
static void der_add(der_t *d, const void *data, size_t len) {
    der_reserve(d, len); memcpy(d->b + d->n, data, len); d->n += len;
}
static void der_u8(der_t *d, unsigned char v) { der_reserve(d, 1); d->b[d->n++] = v; }

static size_t der_begin(der_t *d, unsigned char tag) {
    der_u8(d, tag);
    size_t pos = d->n;
    der_u8(d,0); der_u8(d,0); der_u8(d,0); der_u8(d,0);
    return pos;
}

static void der_end(der_t *d, size_t pos) {
    size_t clen = d->n - pos - 4;
    size_t hl;
    if (clen < 0x80) {
        d->b[pos] = (unsigned char)clen; hl = 1;
    } else if (clen < 0x100) {
        d->b[pos] = 0x81; d->b[pos+1] = (unsigned char)clen; hl = 2;
    } else if (clen < 0x10000) {
        d->b[pos] = 0x82; d->b[pos+1] = (clen >> 8) & 0xFF; d->b[pos+2] = clen & 0xFF; hl = 3;
    } else {
        d->b[pos] = 0x83;
        d->b[pos+1] = (clen >> 16) & 0xFF;
        d->b[pos+2] = (clen >> 8) & 0xFF;
        d->b[pos+3] = clen & 0xFF;
        hl = 4;
    }
    if (hl < 4) {
        memmove(d->b + pos + hl, d->b + pos + 4, clen);
        d->n -= (4 - hl);
    }
}

static void der_tlv(der_t *d, unsigned char tag, const void *data, size_t len) {
    der_u8(d, tag);
    if (len < 0x80) der_u8(d, (unsigned char)len);
    else if (len < 0x100) { der_u8(d, 0x81); der_u8(d, (unsigned char)len); }
    else if (len < 0x10000) {
        der_u8(d, 0x82); der_u8(d, (len >> 8) & 0xFF); der_u8(d, len & 0xFF);
    } else {
        der_u8(d, 0x83);
        der_u8(d, (len >> 16) & 0xFF);
        der_u8(d, (len >> 8) & 0xFF);
        der_u8(d, len & 0xFF);
    }
    der_add(d, data, len);
}

static void der_oid(der_t *d, const unsigned char *oid, size_t oid_len) {
    der_tlv(d, 0x06, oid, oid_len);
}

/* ============================================================ */
/* OID pre-codificati                                            */
/* ============================================================ */
static const unsigned char OID_SIGNED_DATA[]    = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02 };
static const unsigned char OID_SPC_INDIRECT[]   = { 0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x04 };
static const unsigned char OID_SPC_PE_IMAGE[]   = { 0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x0F };
static const unsigned char OID_SHA256[]         = { 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01 };
static const unsigned char OID_CONTENT_TYPE[]   = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x03 };
static const unsigned char OID_MESSAGE_DIGEST[] = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x04 };
static const unsigned char OID_RSA_ENCRYPTION[] = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01 };

/* ============================================================ */
/* Authenticode hash del PE                                      */
/* ============================================================ */
static BOOL auth_hash(const unsigned char *pe, size_t pe_len,
                      unsigned char out[SHA256_DIGEST_LENGTH])
{
    if (pe_len < 0x40) return FALSE;
    uint32_t pe_off = *(const uint32_t *)(pe + 0x3C);
    if (pe_off + 0x18 > pe_len) return FALSE;
    if (memcmp(pe + pe_off, "PE\0\0", 4) != 0) return FALSE;

    uint16_t opt_magic = *(const uint16_t *)(pe + pe_off + 24);
    size_t dd_off;
    if (opt_magic == 0x20b) dd_off = pe_off + 24 + 112;
    else if (opt_magic == 0x10b) dd_off = pe_off + 24 + 96;
    else return FALSE;

    size_t csum_off = pe_off + 24 + 64;
    size_t cert_dd_off = dd_off + 4 * 8;
    if (csum_off + 4 > pe_len || cert_dd_off + 8 > pe_len) return FALSE;

    uint32_t cert_size = *(const uint32_t *)(pe + cert_dd_off + 4);
    uint32_t cert_offset = *(const uint32_t *)(pe + cert_dd_off);
    size_t hash_end = pe_len;
    if (cert_size > 0 && cert_offset > 0 && cert_offset < pe_len)
        hash_end = cert_offset;

    unsigned char *tmp = malloc(hash_end);
    if (!tmp) return FALSE;
    memcpy(tmp, pe, hash_end);
    memset(tmp + csum_off, 0, 4);
    memset(tmp + cert_dd_off, 0, 8);
    SHA256(tmp, hash_end, out);
    free(tmp);
    return TRUE;
}

/* ============================================================ */
/* SpcIndirectDataContent                                        */
/* ============================================================ */
static void build_spc_indirect(const unsigned char hash[SHA256_DIGEST_LENGTH], der_t *out)
{
    der_init(out, 128);
    size_t seq = der_begin(out, 0x30);
    {
        size_t data_seq = der_begin(out, 0x30);
        der_oid(out, OID_SPC_PE_IMAGE, sizeof(OID_SPC_PE_IMAGE));
        static const unsigned char empty_seq[] = { 0x30, 0x00 };
        der_tlv(out, 0xA0, empty_seq, sizeof(empty_seq));
        der_end(out, data_seq);
    }
    {
        size_t di_seq = der_begin(out, 0x30);
        {
            size_t alg_seq = der_begin(out, 0x30);
            der_oid(out, OID_SHA256, sizeof(OID_SHA256));
            der_u8(out, 0x05); der_u8(out, 0x00);
            der_end(out, alg_seq);
        }
        der_tlv(out, 0x04, hash, SHA256_DIGEST_LENGTH);
        der_end(out, di_seq);
    }
    der_end(out, seq);
}

/* ============================================================ */
/* Authenticated attributes                                      */
/* ============================================================ */
static void build_attrs(const unsigned char sid_hash[SHA256_DIGEST_LENGTH],
                        der_t *out, der_t *out_signed)
{
    der_t c; der_init(&c, 256);
    {
        size_t attr = der_begin(&c, 0x30);
        der_oid(&c, OID_CONTENT_TYPE, sizeof(OID_CONTENT_TYPE));
        size_t set = der_begin(&c, 0x31);
        der_oid(&c, OID_SPC_INDIRECT, sizeof(OID_SPC_INDIRECT));
        der_end(&c, set);
        der_end(&c, attr);
    }
    {
        size_t attr = der_begin(&c, 0x30);
        der_oid(&c, OID_MESSAGE_DIGEST, sizeof(OID_MESSAGE_DIGEST));
        size_t set = der_begin(&c, 0x31);
        der_tlv(&c, 0x04, sid_hash, SHA256_DIGEST_LENGTH);
        der_end(&c, set);
        der_end(&c, attr);
    }
    der_init(out, c.n + 8);
    der_tlv(out, 0xA0, c.b, c.n);
    der_init(out_signed, c.n + 8);
    der_tlv(out_signed, 0x31, c.b, c.n);
    der_free(&c);
}

/* ============================================================ */
/* Firma RSA-SHA256                                              */
/* ============================================================ */
static BOOL rsa_sign(EVP_PKEY *pkey, const unsigned char *data, size_t n,
                     unsigned char **out_sig, size_t *out_n)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return FALSE;
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) { EVP_MD_CTX_free(ctx); return FALSE; }
    if (EVP_DigestSignUpdate(ctx, data, n) != 1) { EVP_MD_CTX_free(ctx); return FALSE; }
    size_t sl = 0;
    if (EVP_DigestSignFinal(ctx, NULL, &sl) != 1) { EVP_MD_CTX_free(ctx); return FALSE; }
    unsigned char *sig = malloc(sl);
    if (!sig) { EVP_MD_CTX_free(ctx); return FALSE; }
    if (EVP_DigestSignFinal(ctx, sig, &sl) != 1) { free(sig); EVP_MD_CTX_free(ctx); return FALSE; }
    EVP_MD_CTX_free(ctx);
    *out_sig = sig; *out_n = sl;
    return TRUE;
}

/* ============================================================ */
/* PKCS#7 SignedData (Authenticode)                              */
/* ============================================================ */
static BOOL build_pkcs7(EVP_PKEY *pkey, X509 *x509,
                        const unsigned char *sid_der, size_t sid_len,
                        unsigned char **out_p7, size_t *out_p7_len)
{
    unsigned char sid_hash[SHA256_DIGEST_LENGTH];
    SHA256(sid_der, sid_len, sid_hash);

    der_t attrs_impl, attrs_signed;
    build_attrs(sid_hash, &attrs_impl, &attrs_signed);

    unsigned char *sig = NULL; size_t sig_len = 0;
    if (!rsa_sign(pkey, attrs_signed.b, attrs_signed.n, &sig, &sig_len)) {
        der_free(&attrs_impl); der_free(&attrs_signed); return FALSE;
    }
    der_free(&attrs_signed);

    unsigned char *issuer_der = NULL, *serial_der = NULL;
    int issuer_len = i2d_X509_NAME(X509_get_issuer_name(x509), &issuer_der);
    int serial_len = i2d_ASN1_INTEGER(X509_get_serialNumber(x509), &serial_der);
    unsigned char *cert_der = NULL;
    int cert_len = i2d_X509(x509, &cert_der);

    if (issuer_len <= 0 || serial_len <= 0 || cert_len <= 0) {
        der_free(&attrs_impl); free(sig);
        if (issuer_der) OPENSSL_free(issuer_der);
        if (serial_der) OPENSSL_free(serial_der);
        if (cert_der) OPENSSL_free(cert_der);
        return FALSE;
    }

    /* SignerInfo */
    der_t si; der_init(&si, 512);
    {
        size_t s = der_begin(&si, 0x30);
        static const unsigned char one[] = { 0x01 };
        der_tlv(&si, 0x02, one, 1);
        {
            size_t ias = der_begin(&si, 0x30);
            der_add(&si, issuer_der, issuer_len);
            der_add(&si, serial_der, serial_len);
            der_end(&si, ias);
        }
        {
            size_t alg = der_begin(&si, 0x30);
            der_oid(&si, OID_SHA256, sizeof(OID_SHA256));
            der_u8(&si, 0x05); der_u8(&si, 0x00);
            der_end(&si, alg);
        }
        der_add(&si, attrs_impl.b, attrs_impl.n);
        {
            size_t alg = der_begin(&si, 0x30);
            der_oid(&si, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION));
            der_u8(&si, 0x05); der_u8(&si, 0x00);
            der_end(&si, alg);
        }
        der_tlv(&si, 0x04, sig, sig_len);
        der_end(&si, s);
    }
    der_free(&attrs_impl); free(sig);
    OPENSSL_free(issuer_der); OPENSSL_free(serial_der);

    /* SignedData */
    der_t sd; der_init(&sd, 1024);
    {
        size_t s = der_begin(&sd, 0x30);
        static const unsigned char one[] = { 0x01 };
        der_tlv(&sd, 0x02, one, 1);
        {
            size_t set = der_begin(&sd, 0x31);
            size_t alg = der_begin(&sd, 0x30);
            der_oid(&sd, OID_SHA256, sizeof(OID_SHA256));
            der_u8(&sd, 0x05); der_u8(&sd, 0x00);
            der_end(&sd, alg);
            der_end(&sd, set);
        }
        {
            size_t ci = der_begin(&sd, 0x30);
            der_oid(&sd, OID_SPC_INDIRECT, sizeof(OID_SPC_INDIRECT));
            der_tlv(&sd, 0xA0, sid_der, sid_len);
            der_end(&sd, ci);
        }
        der_tlv(&sd, 0xA0, cert_der, cert_len);
        {
            size_t set = der_begin(&sd, 0x31);
            der_add(&sd, si.b, si.n);
            der_end(&sd, set);
        }
        der_end(&sd, s);
    }
    der_free(&si);
    OPENSSL_free(cert_der);

    /* ContentInfo wrapper */
    der_t ci; der_init(&ci, sd.n + 64);
    {
        size_t s = der_begin(&ci, 0x30);
        der_oid(&ci, OID_SIGNED_DATA, sizeof(OID_SIGNED_DATA));
        der_tlv(&ci, 0xA0, sd.b, sd.n);
        der_end(&ci, s);
    }
    der_free(&sd);

    *out_p7 = ci.b;
    *out_p7_len = ci.n;
    return TRUE;
}

/* ============================================================ */
/* Firma PE e scrittura WIN_CERTIFICATE                          */
/* ============================================================ */
static BOOL sign_pe(const wchar_t *InPath, const wchar_t *OutPath)
{
    size_t pe_len = 0;
    unsigned char *pe = read_file(InPath, &pe_len);
    if (!pe) { fwprintf(stderr, L"[sign] lettura %ls fallita\n", InPath); return FALSE; }

    FILE *fp = _wfopen(KEY_PRIV, L"rb");
    if (!fp) { free(pe); return FALSE; }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) { free(pe); return FALSE; }

    fp = _wfopen(KEY_CERT, L"rb");
    if (!fp) { EVP_PKEY_free(pkey); free(pe); return FALSE; }
    X509 *x509 = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!x509) { EVP_PKEY_free(pkey); free(pe); return FALSE; }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!auth_hash(pe, pe_len, hash)) {
        fwprintf(stderr, L"[sign] auth_hash fallito\n");
        X509_free(x509); EVP_PKEY_free(pkey); free(pe); return FALSE;
    }

    der_t sid; build_spc_indirect(hash, &sid);

    unsigned char *p7_der = NULL; size_t p7_len = 0;
    if (!build_pkcs7(pkey, x509, sid.b, sid.n, &p7_der, &p7_len)) {
        fwprintf(stderr, L"[sign] build_pkcs7 fallito\n");
        der_free(&sid); X509_free(x509); EVP_PKEY_free(pkey); free(pe); return FALSE;
    }
    der_free(&sid); X509_free(x509); EVP_PKEY_free(pkey);

    size_t wc_len = 8 + p7_len;
    size_t wc_aligned = (wc_len + 7) & ~7UL;
    unsigned char *out = malloc(pe_len + wc_aligned);
    if (!out) { free(p7_der); free(pe); return FALSE; }
    memcpy(out, pe, pe_len);

    unsigned char *wc = out + pe_len;
    uint32_t dwLength = (uint32_t)wc_len;
    uint16_t wRevision = 0x0200;
    uint16_t wCertType = 0x0002;
    memcpy(wc + 0, &dwLength, 4);
    memcpy(wc + 4, &wRevision, 2);
    memcpy(wc + 6, &wCertType, 2);
    memcpy(wc + 8, p7_der, p7_len);
    if (wc_aligned > wc_len) memset(wc + wc_len, 0, wc_aligned - wc_len);

    uint32_t pe_off = *(const uint32_t *)(out + 0x3C);
    uint16_t opt_magic = *(const uint16_t *)(out + pe_off + 24);
    size_t dd_off = (opt_magic == 0x20b) ? (pe_off + 24 + 112) : (pe_off + 24 + 96);
    size_t cert_dd_off = dd_off + 4 * 8;
    uint32_t cert_size = (uint32_t)wc_aligned;
    uint32_t cert_offset = (uint32_t)pe_len;
    memcpy(out + cert_dd_off, &cert_offset, 4);
    memcpy(out + cert_dd_off + 4, &cert_size, 4);

    BOOL ok = write_bin(OutPath, out, pe_len + wc_aligned);
    free(out); free(p7_der); free(pe);

    if (ok) wprintf(L"[sign] firmato %ls (%zu byte firma)\n", OutPath, p7_len);
    else    fwprintf(stderr, L"[sign] scrittura fallita\n");
    return ok;
}

/* ============================================================ */
/* BCD                                                           */
/* ============================================================ */
static BOOL install_bcd_entry(const wchar_t *Desc, const wchar_t *EfiPath) {
    char out[16384];
    wchar_t cmd[512];
    _snwprintf(cmd, 512, L"bcdedit /copy {bootmgr} /d \"%ls\"", Desc); cmd[511] = 0;
    if (!run_capture(cmd, out, sizeof(out))) return FALSE;
    char *brace = strchr(out, '{'); if (!brace) return FALSE;
    char *end = strchr(brace, '}'); if (!end) return FALSE; *end = 0;
    wchar_t guid_w[64];
    MultiByteToWideChar(CP_ACP, 0, brace, -1, guid_w, 64);
    _snwprintf(cmd, 512, L"bcdedit /set %ls path %ls", guid_w, EfiPath); cmd[511] = 0;
    if (run_and_wait(cmd) != 0) return FALSE;
    _snwprintf(cmd, 512,
        L"bcdedit /set {fwbootmgr} displayorder %ls /addfirst", guid_w);
    cmd[511] = 0;
    if (run_and_wait(cmd) != 0) return FALSE;
    wprintf(L"[install] voce BCD \"%ls\" -> %ls\n", Desc, EfiPath);
    return TRUE;
}

/* ============================================================ */
/* Task Scheduler                                                */
/* ============================================================ */
static BOOL install_scheduled_task(const wchar_t *WinStagePath) {
    wchar_t cmd[1024];
    _snwprintf(cmd, 1024,
        L"schtasks /create /tn \"" TASK_NAME L"\" "
        L"/tr \"%ls\" /sc onstart /ru SYSTEM /rl highest /f",
        WinStagePath);
    cmd[1023] = 0;
    DWORD ec = run_and_wait(cmd);
    if (ec != 0) { fwprintf(stderr, L"[install] schtasks fallito (ec=%lu)\n", ec); return FALSE; }
    wprintf(L"[install] task \"%ls\" registrato.\n", TASK_NAME);
    return TRUE;
}

/* ============================================================ */
/* Scrittura startup.nsh embedded                                */
/* ============================================================ */
static BOOL write_startup_nsh(const wchar_t *EspRoot, bool custom)
{
    wchar_t path[MAX_PATH];
    _snwprintf(path, MAX_PATH, L"%lsEFI\\EfiStage\\%ls", EspRoot, ESP_STARTUP_NSH);
    path[MAX_PATH-1] = 0;

    const unsigned char *data = custom ? NSH_CUSTOM  : NSH_DEFAULT;
    unsigned int         len  = custom ? NSH_CUSTOM_len : NSH_DEFAULT_len;

    if (!write_bin(path, data, len)) {
        fwprintf(stderr, L"[install] scrittura %ls fallita\n", path);
        return FALSE;
    }
    wprintf(L"[install] scritto %ls (%u byte, embedded)\n", path, len);
    return TRUE;
}

/* ============================================================ */
/* MAIN                                                          */
/* ============================================================ */
int wmain(int argc, wchar_t **argv) {
    if (argc < 3) {
        fwprintf(stderr,
            L"Uso: %ls <efi_stage.efi> <win_stage.exe> [opzioni]\n"
            L"  --custom-keys <dir>   Iscrive chiavi personalizzate (.auth)\n"
            L"  --enroll-default      Iscrive chiavi default Microsoft\n",
            argv[0]);
        return 1;
    }
    if (!is_admin()) {
        fwprintf(stderr, L"[install] servono privilegi di amministratore.\n");
        return 1;
    }

    const wchar_t *EfiSrc = argv[1];
    const wchar_t *WinSrc = argv[2];
    bool customKeys = false;
    wchar_t CustomKeysDir[MAX_PATH] = {0};

    for (int i = 3; i < argc; i++) {
        if (wcscmp(argv[i], L"--custom-keys") == 0 && i + 1 < argc) {
            customKeys = true;
            wcsncpy(CustomKeysDir, argv[++i], MAX_PATH - 1);
        } else if (wcscmp(argv[i], L"--enroll-default") == 0) {
            customKeys = false;
        }
    }

    if (GetFileAttributesW(EfiSrc) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"[install] file non trovato: %ls\n", EfiSrc); return 1;
    }
    if (GetFileAttributesW(WinSrc) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"[install] file non trovato: %ls\n", WinSrc); return 1;
    }

    wchar_t EspRoot[MAX_PATH] = {0};
    if (!find_esp(EspRoot, MAX_PATH)) {
        fwprintf(stderr, L"[install] ESP non trovata.\n"); return 1;
    }
    wprintf(L"[install] ESP: %ls\n", EspRoot);

    wchar_t esp_dir[MAX_PATH];
    _snwprintf(esp_dir, MAX_PATH, L"%lsEFI\\EfiStage", EspRoot);
    esp_dir[MAX_PATH-1] = 0;
    ensure_dir(esp_dir);

    if (!generate_keys()) {
        fwprintf(stderr, L"[install] generazione chiavi fallita.\n"); return 1;
    }

    /* Firma efi_stage.efi */
    wchar_t signed_dst[MAX_PATH];
    _snwprintf(signed_dst, MAX_PATH, L"%lsEFI\\EfiStage\\%ls", EspRoot, ESP_SIGNED_NAME);
    signed_dst[MAX_PATH-1] = 0;
    if (!sign_pe(EfiSrc, signed_dst)) {
        fwprintf(stderr, L"[install] firma fallita.\n"); return 2;
    }

    /* Copia non firmato (per debug) */
    wchar_t unsigned_dst[MAX_PATH];
    _snwprintf(unsigned_dst, MAX_PATH, L"%lsEFI\\EfiStage\\%ls", EspRoot, ESP_EFI_NAME);
    unsigned_dst[MAX_PATH-1] = 0;
    copy_file_or_die(EfiSrc, unsigned_dst);

    /* Copia tool di iscrizione se presenti nella directory corrente */
    wchar_t tool_src[MAX_PATH], tool_dst[MAX_PATH];
    _snwprintf(tool_src, MAX_PATH, L"EnrollDefaultKeys.efi");
    _snwprintf(tool_dst, MAX_PATH, L"%lsEFI\\EfiStage\\%ls", EspRoot, ESP_ENROLL_DEF);
    if (GetFileAttributesW(tool_src) != INVALID_FILE_ATTRIBUTES)
        copy_file_or_die(tool_src, tool_dst);

    _snwprintf(tool_src, MAX_PATH, L"UpdateVars.efi");
    _snwprintf(tool_dst, MAX_PATH, L"%lsEFI\\EfiStage\\%ls", EspRoot, ESP_UPDATE_VARS);
    if (GetFileAttributesW(tool_src) != INVALID_FILE_ATTRIBUTES)
        copy_file_or_die(tool_src, tool_dst);

    /* Copia chiavi .auth personalizzate se richiesto */
    if (customKeys) {
        wchar_t keys_dir_esp[MAX_PATH];
        _snwprintf(keys_dir_esp, MAX_PATH, L"%lsEFI\\EfiStage\\keys", EspRoot);
        keys_dir_esp[MAX_PATH-1] = 0;
        ensure_dir(keys_dir_esp);

        const wchar_t *files[] = { L"PK.auth", L"KEK.auth", L"db.auth" };
        for (int i = 0; i < 3; i++) {
            wchar_t src[MAX_PATH], dst[MAX_PATH];
            _snwprintf(src, MAX_PATH, L"%ls\\%ls", CustomKeysDir, files[i]);
            _snwprintf(dst, MAX_PATH, L"%ls\\%ls", keys_dir_esp, files[i]);
            if (GetFileAttributesW(src) != INVALID_FILE_ATTRIBUTES)
                copy_file_or_die(src, dst);
        }
    }

    /* Copia win_stage.exe su C:\ProgramData\MyApp\ */
    ensure_dir(WIN_STAGE_DIR);
    wchar_t win_dst[MAX_PATH];
    _snwprintf(win_dst, MAX_PATH, L"%ls\\%ls", WIN_STAGE_DIR, WIN_STAGE_NAME);
    win_dst[MAX_PATH-1] = 0;
    copy_file_or_die(WinSrc, win_dst);

    /* Scrivi startup.nsh embedded */
    if (!write_startup_nsh(EspRoot, customKeys)) {
        fwprintf(stderr, L"[install] startup.nsh fallito.\n"); return 3;
    }

    /* BCD per efi_stage_signed.efi */
    wchar_t signed_path[MAX_PATH];
    _snwprintf(signed_path, MAX_PATH, L"\\EFI\\EfiStage\\%ls", ESP_SIGNED_NAME);
    signed_path[MAX_PATH-1] = 0;
    if (!install_bcd_entry(BCD_DESC, signed_path)) {
        fwprintf(stderr, L"[install] BCD fallita.\n"); return 4;
    }

    /* Task Scheduler */
    if (!install_scheduled_task(win_dst)) {
        fwprintf(stderr, L"[install] task fallito.\n"); return 5;
    }

    wprintf(L"\n[install] FATTO.\n"
            L"  - EFI firmato : %ls\n"
            L"  - Win stage   : %ls\n"
            L"  - Chiavi MOK  : %ls\n"
            L"  - startup.nsh : %lsEFI\\EfiStage\\%ls (%ls)\n"
            L"\n"
            L"Prossimi passi:\n"
            L"  1. Riavvia. La UEFI Shell eseguirà automaticamente startup.nsh.\n"
            L"  2. Le chiavi verranno iscritte e il sistema si riavvierà.\n"
            L"  3. Al riavvio successivo, Secure Boot sarà attivo.\n"
            L"\nRiavvio tra 15 secondi. CTRL+C per annullare.\n",
            signed_dst, win_dst, KEY_DIR,
            EspRoot, ESP_STARTUP_NSH,
            customKeys ? L"custom" : L"default");

    for (int i = 15; i > 0; --i) { wprintf(L"  %d...\r", i); Sleep(1000); }
    wprintf(L"\n");
    if (run_and_wait(L"shutdown /r /t 0") != 0) {
        fwprintf(stderr, L"[install] shutdown fallito.\n"); return 6;
    }
    return 0;
}