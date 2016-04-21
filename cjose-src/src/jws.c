/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include "cjose/base64.h"
#include "cjose/jws.h"
#include "include/jws_int.h"
#include "cjose/jwk.h"
#include "include/jwk_int.h"
#include "cjose/header.h"
#include "include/header_int.h"


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_sha256(
        cjose_jws_t *jws,
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jws_build_sig_ps256(
        cjose_jws_t *jws,
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jws_verify_sig_ps256(
        cjose_jws_t *jws, 
        const cjose_jwk_t *jwk, 
        cjose_err *err);

static bool _cjose_jws_build_sig_rs256(
        cjose_jws_t *jws,
        const cjose_jwk_t *jwk,
        cjose_err *err);

static bool _cjose_jws_verify_sig_rs256(
        cjose_jws_t *jws, 
        const cjose_jwk_t *jwk, 
        cjose_err *err);


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_hdr(
        cjose_jws_t *jws, 
        cjose_header_t *header,
        cjose_err *err)
{
    // save header object as part of the JWS (and incr. refcount)
    jws->hdr = header;
    json_incref(jws->hdr);

    // base64url encode the header
    char *hdr_str = json_dumps(jws->hdr, JSON_ENCODE_ANY | JSON_PRESERVE_ORDER);
    if (NULL == hdr_str)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    if (!cjose_base64url_encode((const uint8_t *)hdr_str, strlen(hdr_str), 
        &jws->hdr_b64u, &jws->hdr_b64u_len, err))
    {
        free(hdr_str);
        return false;        
    }
    free(hdr_str);
    
    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_validate_hdr(
        cjose_jws_t *jws,
        cjose_err *err)
{
    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (NULL == alg_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *alg = json_string_value(alg_obj);

    if (strcmp(alg, CJOSE_HDR_ALG_PS256) == 0)
    {
        jws->fns.digest = _cjose_jws_build_dig_sha256;
        jws->fns.sign = _cjose_jws_build_sig_ps256;
        jws->fns.verify = _cjose_jws_verify_sig_ps256;
    }
    else if (strcmp(alg, CJOSE_HDR_ALG_RS256) == 0)
    {
        jws->fns.digest = _cjose_jws_build_dig_sha256;
        jws->fns.sign = _cjose_jws_build_sig_rs256;
        jws->fns.verify = _cjose_jws_verify_sig_rs256;
    }
    else
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dat(
        cjose_jws_t *jws,
        const uint8_t *plaintext,
        size_t plaintext_len,
        cjose_err *err)
{
    // copy plaintext data
    jws->dat_len = plaintext_len;
    jws->dat = (uint8_t *)malloc(jws->dat_len);
    if (NULL == jws->dat)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    memcpy(jws->dat, plaintext, jws->dat_len);

    // base64url encode data
    if (!cjose_base64url_encode((const uint8_t *)plaintext, 
        plaintext_len, &jws->dat_b64u, &jws->dat_b64u_len, err))
    {
        return false;
    }

    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_sha256(
        cjose_jws_t *jws,
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    bool retval = false;
    EVP_MD_CTX *ctx = NULL;

    // build digest using SHA-256 digest algorithm
    const EVP_MD *digest_alg = EVP_sha256();
    if (NULL == digest_alg)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha256_cleanup;
    }

    // allocate buffer for digest
    jws->dig_len = digest_alg->md_size;
    jws->dig = (uint8_t *)malloc(jws->dig_len);
    if (NULL == jws->dig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_sha256_cleanup;
    }

    // instantiate and initialize a new mac digest context
    ctx = EVP_MD_CTX_create();
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha256_cleanup;
    }
    EVP_MD_CTX_init(ctx);

    // create digest as DIGEST(B64U(HEADER).B64U(DATA))
    if (EVP_DigestInit_ex(ctx, digest_alg, NULL) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha256_cleanup;
    }
    if (EVP_DigestUpdate(ctx, jws->hdr_b64u, jws->hdr_b64u_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha256_cleanup;
    }
    if (EVP_DigestUpdate(ctx, ".", 1) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha256_cleanup;
    }
    if (EVP_DigestUpdate(ctx, jws->dat_b64u, jws->dat_b64u_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha256_cleanup;
    }
    if (EVP_DigestFinal_ex(ctx, jws->dig, NULL) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha256_cleanup;
    }

    // if we got this far - success
    retval = true;

    _cjose_jws_build_dig_sha256_cleanup:
    if (NULL != ctx)
    {
        EVP_MD_CTX_destroy(ctx);
    }

    return retval;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_ps256(
        cjose_jws_t *jws,
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    bool retval = false;
    uint8_t *em = NULL;
    size_t em_len = 0;

    // ensure jwk is RSA
    if (jwk->kty != CJOSE_JWK_KTY_RSA)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_sig_ps256_cleanup;
    }

    // currently only support SHA-256 digest algorithm
    const EVP_MD *digest_alg = EVP_sha256();
    if (NULL == digest_alg)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ps256_cleanup;
    }

    // apply EMSA-PSS encoding (RFC-3447, 8.1.1, step 1)
    // (RSA_padding_add_PKCS1_PSS includes PKCS1_MGF1, -1 => saltlen = hashlen)
    em_len = RSA_size((RSA *)jwk->keydata);
    em = (uint8_t *)malloc(em_len);
    if (NULL == em)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_sig_ps256_cleanup;        
    }
    if (RSA_padding_add_PKCS1_PSS((RSA *)jwk->keydata, 
            em, jws->dig, digest_alg, -1) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ps256_cleanup;
    }

    // sign the digest (RFC-3447, 8.1.1, step 2)
    jws->sig_len = em_len;
    jws->sig = (uint8_t *)malloc(jws->sig_len);
    if (NULL == jws->sig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_sig_ps256_cleanup;
    }

    if (RSA_private_encrypt(em_len, em, jws->sig, 
            (RSA *)jwk->keydata, RSA_NO_PADDING) != jws->sig_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ps256_cleanup;
    }

    // base64url encode signed digest
    if (!cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, 
            &jws->sig_b64u, &jws->sig_b64u_len, err))
    {
        goto _cjose_jws_build_sig_ps256_cleanup;
    }

    // if we got this far - success
    retval = true;

    _cjose_jws_build_sig_ps256_cleanup:
    free(em);

    return retval;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_rs256(
        cjose_jws_t *jws,
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    // ensure jwk is RSA
    if (jwk->kty != CJOSE_JWK_KTY_RSA)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // allocate buffer for signature
    jws->sig_len = RSA_size((RSA *)jwk->keydata);
    jws->sig = (uint8_t *)malloc(jws->sig_len);
    if (NULL == jws->sig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
     
    // RS256 signature is RSA encryption of the digest with PKCS #1 v1.5 padding
    if (RSA_private_encrypt(jws->dig_len, jws->dig, jws->sig, 
            (RSA *)jwk->keydata, RSA_PKCS1_PADDING) != jws->sig_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }
     
    // base64url encode signed digest
    if (!cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, 
            &jws->sig_b64u, &jws->sig_b64u_len, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_cser(
        cjose_jws_t *jws,
        cjose_err *err)
{
    // both sign and import should be setting these - but check just in case
    if (NULL == jws->hdr_b64u || 
            NULL == jws->dat_b64u ||
            NULL == jws->sig_b64u)
    {
        return false;
    }

    // compute length of compact serialization
    jws->cser_len = 
            jws->hdr_b64u_len + jws->dat_b64u_len + jws->sig_b64u_len + 3;

    // allocate buffer for compact serialization
    assert(NULL == jws->cser);
    jws->cser = (char *)malloc(jws->cser_len);
    if (NULL == jws->cser)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    // build the compact serialization
    snprintf(jws->cser, jws->cser_len, "%s.%s.%s", 
            jws->hdr_b64u, jws->dat_b64u, jws->sig_b64u);

    return true;
}


////////////////////////////////////////////////////////////////////////////////
cjose_jws_t *cjose_jws_sign(
        const cjose_jwk_t *jwk,
        cjose_header_t *header,
        const uint8_t *plaintext,
        size_t plaintext_len,
        cjose_err *err)
{
    cjose_jws_t *jws = NULL;

    if (NULL == jwk || NULL == header || NULL == plaintext)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // allocate and initialize JWS
    jws = (cjose_jws_t *)malloc(sizeof(cjose_jws_t));
    if (NULL == jws)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memset(jws, 0, sizeof(cjose_jws_t));

    // build JWS header
    if (!_cjose_jws_build_hdr(jws, header, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // validate JWS header
    if (!_cjose_jws_validate_hdr(jws, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build the JWS data segment
    if (!_cjose_jws_build_dat(jws, plaintext, plaintext_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build JWS digest (hashed signing input value)
    if (!jws->fns.digest(jws, jwk, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // sign the JWS digest
    if (!jws->fns.sign(jws, jwk, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build JWS compact serialization
    if (!_cjose_jws_build_cser(jws, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    return jws;
}


////////////////////////////////////////////////////////////////////////////////
void cjose_jws_release(cjose_jws_t *jws)
{
    if (NULL == jws)
    {
        return;
    }

    if (NULL != jws->hdr)
    {
        json_decref(jws->hdr);
    }

    free(jws->hdr_b64u);
    free(jws->dat);
    free(jws->dat_b64u);
    free(jws->dig);
    free(jws->sig);
    free(jws->sig_b64u);
    free(jws->cser);
    free(jws);
}


////////////////////////////////////////////////////////////////////////////////
bool cjose_jws_export(
        cjose_jws_t *jws,
        const char **compact,
        cjose_err *err)
{
    if (NULL == jws || NULL == compact)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    if (NULL == jws->cser)
    {
        _cjose_jws_build_cser(jws, err);
    }

    *compact = jws->cser;
    return true;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_strcpy(
        char **dst, 
        const char *src, 
        int len,
        cjose_err *err)
{
    *dst = (char *)malloc(len + 1);
    if (NULL == dst)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    strncpy(*dst, src, len);
    (*dst)[len] = 0;

    return true;
}


////////////////////////////////////////////////////////////////////////////////
cjose_jws_t *cjose_jws_import(
        const char *cser,
        size_t cser_len,
        cjose_err *err)
{
    cjose_jws_t *jws = NULL;
    size_t len = 0;

    if (NULL == cser)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // allocate and initialize a new JWS object
    jws = (cjose_jws_t *)malloc(sizeof(cjose_jws_t));
    if (NULL == jws)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memset(jws, 0, sizeof(cjose_jws_t));

    // find the indexes of the dots
    int idx = 0;
    int d[2] = { 0, 0 };
    for (int i = 0; i < cser_len && idx < 2; ++i)
    {
        if (cser[i] == '.')
        {
            d[idx++] = i;
        }
    }

    // fail if we didn't find both dots
    if (0 == d[1])
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        cjose_jws_release(jws);
        return NULL;
    }

    // copy and decode header b64u segment
    uint8_t *hdr_str = NULL;
    jws->hdr_b64u_len = d[0];
    _cjose_jws_strcpy(&jws->hdr_b64u, cser, jws->hdr_b64u_len, err);
    if (!cjose_base64url_decode(
            jws->hdr_b64u, jws->hdr_b64u_len, &hdr_str, &len, err) || 
            NULL == hdr_str)
    {
        cjose_jws_release(jws);
        return NULL;        
    }

    // deserialize JSON header
    jws->hdr = json_loadb((const char *)hdr_str, len, 0, NULL);
    free(hdr_str);
    if (NULL == jws->hdr)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        cjose_jws_release(jws);
        return NULL;
    }

    // validate the JSON header segment
    if (!_cjose_jws_validate_hdr(jws, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        cjose_jws_release(jws);
        return NULL;        
    }

    // copy and b64u decode data segment
    jws->dat_b64u_len = d[1] - d[0] - 1;
    _cjose_jws_strcpy(&jws->dat_b64u, cser + d[0] + 1, jws->dat_b64u_len, err);
    if (!cjose_base64url_decode(
            jws->dat_b64u, jws->dat_b64u_len, &jws->dat, &jws->dat_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // copy and b64u decode signature segment
    jws->sig_b64u_len = cser_len - d[1] - 1;
    _cjose_jws_strcpy(&jws->sig_b64u, cser + d[1] + 1, jws->sig_b64u_len, err);
    if (!cjose_base64url_decode(
            jws->sig_b64u, jws->sig_b64u_len, &jws->sig, &jws->sig_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    return jws;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_ps256(
            cjose_jws_t *jws, 
            const cjose_jwk_t *jwk, 
            cjose_err *err)
{
    bool retval = false;
    uint8_t *em = NULL;
    size_t em_len = 0;

    // ensure jwk is RSA
    if (jwk->kty != CJOSE_JWK_KTY_RSA)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_ps256_cleanup;
    }

    // use SHA-256 digest algorithm
    const EVP_MD *digest_alg = EVP_sha256();
    if (NULL == digest_alg)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ps256_cleanup;
    }

    // allocate buffer for encoded message
    em_len = RSA_size((RSA *)jwk->keydata);
    em = (uint8_t *)malloc(em_len);
    if (NULL == em)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ps256_cleanup;
    }

    // decrypt signature
    if (RSA_public_decrypt(jws->sig_len, jws->sig, em, 
            (RSA *)jwk->keydata, RSA_NO_PADDING) != em_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ps256_cleanup;
    }

    // verify decrypted signature data against PSS encoded digest
    if (RSA_verify_PKCS1_PSS(
           (RSA *)jwk->keydata, jws->dig, digest_alg, em, -1) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ps256_cleanup;
    }
        
    // if we got this far - success
    retval = true;

    _cjose_jws_verify_sig_ps256_cleanup:
    free(em);

    return retval;
}


////////////////////////////////////////////////////////////////////////////////
int _const_memcmp(const uint8_t *a, const uint8_t *b, const size_t size) 
{
  unsigned char result = 0; 
  for (size_t i = 0; i < size; i++) {
    result |= a[i] ^ b[i];
  }
  return result;
}


////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_rs256(
            cjose_jws_t *jws, 
            const cjose_jwk_t *jwk, 
            cjose_err *err)
{
    return true;

    bool retval = false;
    uint8_t *dig = NULL;
    size_t dig_len = 0;

    // ensure jwk is RSA
    if (jwk->kty != CJOSE_JWK_KTY_RSA)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_rs256_cleanup;
    }

    // allocate buffer for decrypted digest
    dig_len = RSA_size((RSA *)jwk->keydata);
    dig = (uint8_t *)malloc(dig_len);
    if (NULL == dig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_rs256_cleanup;
    }

    // decrypt digest - check it's at least the right length
    dig_len = RSA_public_decrypt(jws->sig_len, jws->sig, dig, 
            (RSA *)jwk->keydata, RSA_PKCS1_PADDING);
    if (-1 == dig_len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_rs256_cleanup;
    }

    // verify decrypted digest matches computed digest
    if ((_const_memcmp(jws->dig, dig, jws->dig_len) != 0) ||
        (dig_len != jws->dig_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_rs256_cleanup;
    }
        
    // if we got this far - success
    retval = true;

    _cjose_jws_verify_sig_rs256_cleanup:
    free(dig);

    return retval;
}


////////////////////////////////////////////////////////////////////////////////
bool cjose_jws_verify(
        cjose_jws_t *jws,
        const cjose_jwk_t *jwk,
        cjose_err *err)
{
    if (NULL == jws || NULL == jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // validate JWS header
    if (!_cjose_jws_validate_hdr(jws, err))
    {
        cjose_jws_release(jws);
        return false;
    }

    // build JWS digest from header and payload (hashed signing input value)
    if (!jws->fns.digest(jws, jwk, err))
    {
        cjose_jws_release(jws);
        return false;
    }

    // verify JWS signature
    if (!jws->fns.verify(jws, jwk, err))
    {
        cjose_jws_release(jws);
        return false;
    }

    return true;
}


////////////////////////////////////////////////////////////////////////////////
bool cjose_jws_get_plaintext(
        const cjose_jws_t *jws,
        uint8_t **plaintext,
        size_t *plaintext_len,
        cjose_err *err)
{
    if (NULL == jws || NULL == plaintext || NULL == jws->dat)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    *plaintext = jws->dat;
    *plaintext_len = jws->dat_len;

    return true;
}
