/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <cjose/jwk.h>

#include <jansson.h>
#include <openssl/ec.h>

#ifndef SRC_JWK_INT_H
#define SRC_JWK_INT_H

// key-specific function table
typedef struct _key_fntable_int
{
    void (*free)(cjose_jwk_t *);
    bool (*public_json)(const cjose_jwk_t *, json_t *, cjose_err *err);
    bool (*private_json)(const cjose_jwk_t *, json_t *, cjose_err *err);
} key_fntable;

// JSON Web Key structure
struct _cjose_jwk_int
{
    cjose_jwk_kty_t     kty;
    char              * kid;
    unsigned int        retained;
    size_t              keysize;
    void *              keydata;
    const key_fntable * fns;
};

// EC-specific keydata
typedef struct _ec_keydata_int
{
    cjose_jwk_ec_curve  crv;
    EC_KEY *            key;
} ec_keydata;

// RSA-specific keydata = OpenSSL RSA struct
// (just uses RSA struct)

// HKDF implementation, note it currrently supports only SHA256, no info
// and okm must be exactly 32 bytes.
bool cjose_jwk_hkdf(
        const EVP_MD *md,
        const uint8_t *salt,
        size_t salt_len,
        const uint8_t *info,
        size_t info_len,
        const uint8_t *ikm, 
        size_t ikm_len, 
        uint8_t *okm,
        unsigned int okm_len,
        cjose_err *err);

#endif // SRC_JWK_INT_H
