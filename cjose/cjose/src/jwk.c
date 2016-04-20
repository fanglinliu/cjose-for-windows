/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include "include/jwk_int.h"

#include <cjose/base64.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// internal data structures

static const char CJOSE_JWK_EC_P_256_STR[] = "P-256";
static const char CJOSE_JWK_EC_P_384_STR[] = "P-384";
static const char CJOSE_JWK_EC_P_521_STR[] = "P-521";
static const char CJOSE_JWK_KTY_STR[]      = "kty";
static const char CJOSE_JWK_KID_STR[]      = "kid";
static const char CJOSE_JWK_KTY_EC_STR[]   = "EC";
static const char CJOSE_JWK_KTY_RSA_STR[]  = "RSA";
static const char CJOSE_JWK_KTY_OCT_STR[]  = "oct";
static const char CJOSE_JWK_CRV_STR[]      = "crv";
static const char CJOSE_JWK_X_STR[]        = "x";
static const char CJOSE_JWK_Y_STR[]        = "y";
static const char CJOSE_JWK_D_STR[]        = "d";
static const char CJOSE_JWK_N_STR[]        = "n";
static const char CJOSE_JWK_E_STR[]        = "e";
static const char CJOSE_JWK_P_STR[]        = "p";
static const char CJOSE_JWK_Q_STR[]        = "q";
static const char CJOSE_JWK_DP_STR[]       = "dp";
static const char CJOSE_JWK_DQ_STR[]       = "dq";
static const char CJOSE_JWK_QI_STR[]       = "qi";
static const char CJOSE_JWK_K_STR[]        = "k";

static const char * JWK_KTY_NAMES[] = {
    CJOSE_JWK_KTY_RSA_STR,
    CJOSE_JWK_KTY_EC_STR,
    CJOSE_JWK_KTY_OCT_STR
};

// interface functions -- Generic

const char * cjose_jwk_name_for_kty(cjose_jwk_kty_t kty, cjose_err *err)
{
    if (0 == kty || CJOSE_JWK_KTY_OCT < kty)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    return JWK_KTY_NAMES[kty - CJOSE_JWK_KTY_RSA];
}

cjose_jwk_t * cjose_jwk_retain(cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    ++(jwk->retained);
    // TODO: check for overflow

    return jwk;
}

bool cjose_jwk_release(cjose_jwk_t *jwk)
{
    if (!jwk)
    {
        return false;
    }

    --(jwk->retained);
    if (0 == jwk->retained)
    {
        free(jwk->kid);
        jwk->kid = NULL;

        // assumes freefunc is set
        assert(NULL != jwk->fns->free);
        jwk->fns->free(jwk);
        jwk = NULL;
    }

    return (NULL != jwk);
}

cjose_jwk_kty_t cjose_jwk_get_kty(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return -1;
    }

    return jwk->kty;
}

const char *cjose_jwk_get_kid(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    return jwk->kid;
}

bool cjose_jwk_set_kid(
        cjose_jwk_t *jwk, 
        const char *kid, 
        size_t len, 
        cjose_err *err)
{
    if (!jwk || !kid)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    if (jwk->kid)
    {
        free(jwk->kid);
    }    
    jwk->kid = (char *)malloc(len+1);
    if (!jwk->kid)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    strncpy(jwk->kid, kid, len+1);
    return true;
}

char *cjose_jwk_to_json(const cjose_jwk_t *jwk, bool priv, cjose_err *err)
{
    char *result = NULL;

    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    json_t *json = json_object(),
                *field = NULL;
    if (!json)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }

    // set kty
    const char *kty = cjose_jwk_name_for_kty(jwk->kty, err);
    field = json_string(kty);
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }
    json_object_set(json, "kty", field);
    json_decref(field);
    field = NULL;

    // set kid
    if (NULL != jwk->kid)
    {
        field = json_string(jwk->kid);
        if (!field)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto to_json_cleanup;
        }
        json_object_set(json, CJOSE_JWK_KID_STR, field);
        json_decref(field);
        field = NULL;
    }

    // set public fields
    if (jwk->fns->public_json && !jwk->fns->public_json(jwk, json, err))
    {
        goto to_json_cleanup;
    }

    // set private fields
    if (priv && jwk->fns->private_json && 
            !jwk->fns->private_json(jwk, json, err))
    {
        goto to_json_cleanup;
    }

    // generate the string ...
    char *str_jwk = json_dumps(
            json, JSON_ENCODE_ANY | JSON_COMPACT | JSON_PRESERVE_ORDER);
    if (!str_jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }
    result = strdup(str_jwk);
    free(str_jwk);
    
    to_json_cleanup:
    if (json)
    {
        json_decref(json);
        json = NULL;
    }
    if (field)
    {
        json_decref(field);
        field = NULL;
    }
    
    return result;
}

//////////////// Octet String ////////////////
// internal data & functions -- Octet String

static void _oct_free(cjose_jwk_t *jwk);
static bool _oct_public_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _oct_private_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable OCT_FNTABLE = {
    _oct_free,
    _oct_public_fields,
    _oct_private_fields
};

static cjose_jwk_t *_oct_new(uint8_t *buffer, size_t keysize, cjose_err *err)
{
    cjose_jwk_t *jwk = (cjose_jwk_t *)malloc(sizeof(cjose_jwk_t));
    if (NULL == jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
    }
    else
    {
        memset(jwk, 0, sizeof(cjose_jwk_t));
        jwk->retained = 1;
        jwk->kty = CJOSE_JWK_KTY_OCT;
        jwk->keysize = keysize;
        jwk->keydata = buffer;
        jwk->fns = &OCT_FNTABLE;
    }

    return jwk;
}

static void _oct_free(cjose_jwk_t *jwk)
{
    uint8_t *   buffer = (uint8_t *)jwk->keydata;
    jwk->keydata =  NULL;
    if (buffer)
    {
        free(buffer);
    }
    free(jwk);
}

static bool _oct_public_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    return true;
}

static bool _oct_private_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    json_t *field = NULL;
    char *k = NULL;
    size_t klen = 0;
    uint8_t *keydata = (uint8_t *)jwk->keydata;
    size_t keysize = jwk->keysize / 8;

    if (!cjose_base64url_encode(keydata, keysize, &k, &klen, err))
    {
        return false;
    }

    field = json_stringn(k, klen);
    free(k);
    k = NULL;
    if (!field)
    {
        return false;
    }
    json_object_set(json, "k", field);
    json_decref(field);
    
    return true;
}

// interface functions -- Octet String

cjose_jwk_t *cjose_jwk_create_oct_random(size_t keysize, cjose_err *err)
{
    cjose_jwk_t *           jwk = NULL;
    uint8_t *               buffer = NULL;

    if (0 == keysize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_oct_failed;
    }

    // resize to bytes
    size_t buffersize = sizeof(uint8_t) * (keysize / 8);

    buffer = (uint8_t *)malloc(buffersize);
    if (NULL == buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_oct_failed;
    }
    if (1 != RAND_bytes(buffer, buffersize))
    {
        goto create_oct_failed;
    }

    jwk = _oct_new(buffer, keysize, err);
    if (NULL == jwk)
    {
        goto create_oct_failed;
    }
    return jwk;

    create_oct_failed:
    if (buffer)
    {
        free(buffer);
        buffer = NULL;
    }

    return NULL;
}

cjose_jwk_t * cjose_jwk_create_oct_spec(
        const uint8_t *data, size_t len, cjose_err *err)
{
    cjose_jwk_t *           jwk = NULL;
    uint8_t *               buffer = NULL;

    if (NULL == data || 0 == len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_oct_failed;
    }

    buffer = (uint8_t *)malloc(len);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_oct_failed;
    }
    memcpy(buffer, data, len);

    jwk = _oct_new(buffer, len * 8, err);
    if (NULL == jwk)
    {
        goto create_oct_failed;
    }

    return jwk;

    create_oct_failed:
    if (buffer)
    {
        free(buffer);
        buffer = NULL;
    }

    return NULL;
}

//////////////// Elliptic Curve ////////////////
// internal data & functions -- Elliptic Curve

static void _EC_free(cjose_jwk_t *jwk);
static bool _EC_public_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _EC_private_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable EC_FNTABLE = {
    _EC_free,
    _EC_public_fields,
    _EC_private_fields
};

static inline uint8_t _ec_size_for_curve(
        cjose_jwk_ec_curve crv, cjose_err *err)
{
    switch (crv)
    {
        case CJOSE_JWK_EC_P_256: return 32;
        case CJOSE_JWK_EC_P_384: return 48;
        case CJOSE_JWK_EC_P_521: return 66;
    }

    return 0;
}

static inline const char *_ec_name_for_curve(
        cjose_jwk_ec_curve crv, cjose_err *err)
{
    switch (crv)
    {
        case CJOSE_JWK_EC_P_256: return CJOSE_JWK_EC_P_256_STR;
        case CJOSE_JWK_EC_P_384: return CJOSE_JWK_EC_P_384_STR;
        case CJOSE_JWK_EC_P_521: return CJOSE_JWK_EC_P_521_STR;
    }

    return NULL;
}

static inline bool _ec_curve_from_name(
        const char *name, cjose_jwk_ec_curve *crv, cjose_err *err)
{
    bool retval = true;
    if (strncmp(
            name, CJOSE_JWK_EC_P_256_STR, sizeof(CJOSE_JWK_EC_P_256_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_256;
    }
    else if (strncmp(
            name, CJOSE_JWK_EC_P_384_STR, sizeof(CJOSE_JWK_EC_P_384_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_384;
    }
    else if (strncmp(
            name, CJOSE_JWK_EC_P_521_STR, sizeof(CJOSE_JWK_EC_P_521_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_521;
    }
    else
    {
        retval = false;
    }
    return retval;
}

static inline bool _kty_from_name(
        const char *name, cjose_jwk_kty_t *kty, cjose_err *err)
{
    bool retval = true;
    if (strncmp(
            name, CJOSE_JWK_KTY_EC_STR, sizeof(CJOSE_JWK_KTY_EC_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_EC;
    }
    else if (strncmp(
            name, CJOSE_JWK_KTY_RSA_STR, sizeof(CJOSE_JWK_KTY_RSA_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_RSA;
    }
    else if (strncmp(
            name, CJOSE_JWK_KTY_OCT_STR, sizeof(CJOSE_JWK_KTY_OCT_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_OCT;
    }
    else
    {
        retval = false;
    }
    return retval;
}

static cjose_jwk_t *_EC_new(cjose_jwk_ec_curve crv, EC_KEY *ec, cjose_err *err)
{
    ec_keydata *keydata = malloc(sizeof(ec_keydata));
    if (!keydata)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    keydata->crv = crv;
    keydata->key = ec;

    cjose_jwk_t *jwk = malloc(sizeof(cjose_jwk_t));
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        free(keydata);
        return NULL;
    }
    memset(jwk, 0, sizeof(cjose_jwk_t));
    jwk->retained = 1;
    jwk->kty = CJOSE_JWK_KTY_EC;
    switch (crv) {
        case CJOSE_JWK_EC_P_256:
            jwk->keysize = 256;
            break;
        case CJOSE_JWK_EC_P_384:
            jwk->keysize = 384;
            break;
        case CJOSE_JWK_EC_P_521:
            jwk->keysize = 521;
            break;
    }
    jwk->keydata = keydata;
    jwk->fns = &EC_FNTABLE;

    return jwk;
}

static void _EC_free(cjose_jwk_t *jwk)
{
    ec_keydata  *keydata = (ec_keydata *)jwk->keydata;
    jwk->keydata = NULL;

    if (keydata)
    {
        EC_KEY  *ec = keydata->key;
        keydata->key = NULL;
        if (ec)
        {
            EC_KEY_free(ec);
        }
        free(keydata);
    }
    free(jwk);
}

static bool _EC_public_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    ec_keydata      *keydata = (ec_keydata *)jwk->keydata;
    const EC_GROUP  *params = NULL;
    const EC_POINT  *pub = NULL;
    BIGNUM          *bnX = NULL,
                    *bnY = NULL;
    uint8_t         *buffer = NULL;
    char            *b64u = NULL;
    size_t          len = 0,
                    offset = 0;
    json_t          *field = NULL;
    bool            result = false;

    // track expected binary data size
    uint8_t     numsize = _ec_size_for_curve(keydata->crv, err);

    // output the curve
    field = json_string(_ec_name_for_curve(keydata->crv, err));
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "crv", field);
    json_decref(field);
    field = NULL;

    // obtain the public key
    pub = EC_KEY_get0_public_key(keydata->key);
    params = EC_KEY_get0_group(keydata->key);
    if (!pub || !params)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _ec_to_string_cleanup;
    }

    buffer = malloc(numsize);
    bnX = BN_new();
    bnY = BN_new();
    if (!buffer || !bnX || !bnY)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }
    if (1 != EC_POINT_get_affine_coordinates_GFp(params, pub, bnX, bnY, NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }

    // output the x coordinate
    offset = numsize - BN_num_bytes(bnX);
    memset(buffer, 0, numsize);
    BN_bn2bin(bnX, (buffer + offset));
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = json_stringn(b64u, len);
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "x", field);
    json_decref(field);
    field = NULL;
    free(b64u);
    b64u = NULL;

    // output the y coordinate
    offset = numsize - BN_num_bytes(bnY);
    memset(buffer, 0, numsize);
    BN_bn2bin(bnY, (buffer + offset));
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = json_stringn(b64u, len);
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "y", field);
    json_decref(field);
    field = NULL;
    free(b64u);
    b64u = NULL;

    result = true;

    _ec_to_string_cleanup:
    if (field)
    {
        json_decref(field);
    }
    if (bnX)
    {
        BN_free(bnX);
    }
    if (bnY)
    {
        BN_free(bnY);
    }
    if (buffer)
    {
        free(buffer);
    }
    if (b64u)
    {
        free(b64u);
    }

    return result;
}

static bool _EC_private_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    ec_keydata      *keydata = (ec_keydata *)jwk->keydata;
    const BIGNUM    *bnD = EC_KEY_get0_private_key(keydata->key);
    uint8_t         *buffer = NULL;
    char            *b64u = NULL;
    size_t          len = 0,
                    offset = 0;
    json_t          *field = NULL;
    bool            result = false;

    // track expected binary data size
    uint8_t     numsize = _ec_size_for_curve(keydata->crv, err);

    if (!bnD)
    {
        return true;
    }

    buffer = malloc(numsize);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }

    offset = numsize - BN_num_bytes(bnD);
    memset(buffer, 0, numsize);
    BN_bn2bin(bnD, (buffer + offset));
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = json_stringn(b64u, len);
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "d", field);
    json_decref(field);
    field = NULL;
    free(b64u);
    b64u = NULL;

    result = true;

    _ec_to_string_cleanup:
    if (buffer)
    {
        free(buffer);
    }

    return result;
}

// interface functions -- Elliptic Curve

cjose_jwk_t *cjose_jwk_create_EC_random(cjose_jwk_ec_curve crv, cjose_err *err)
{
    cjose_jwk_t *   jwk = NULL;
    EC_KEY *        ec = NULL;

    ec = EC_KEY_new_by_curve_name(crv);
    if (!ec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_EC_failed;
    }
    
    if (1 != EC_KEY_generate_key(ec))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_EC_failed;
    }

    jwk = _EC_new(crv, ec, err);
    if (!jwk)
    {
        goto create_EC_failed;
    }

    return jwk;

    create_EC_failed:
    if (jwk)
    {
        free(jwk);
        jwk = NULL;
    }
    if (ec)
    {
        EC_KEY_free(ec);
        ec = NULL;
    }

    return NULL;
}

cjose_jwk_t *cjose_jwk_create_EC_spec(
        const cjose_jwk_ec_keyspec *spec, cjose_err *err)
{
    cjose_jwk_t *   jwk = NULL;
    EC_KEY *        ec = NULL;
    EC_GROUP *      params = NULL;
    EC_POINT *      Q = NULL;
    BIGNUM *        bnD = NULL;
    BIGNUM *        bnX = NULL;
    BIGNUM *        bnY = NULL;

    if (!spec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    bool            hasPriv = (NULL != spec->d && 0 < spec->dlen);
    bool            hasPub = ((NULL != spec->x && 0 < spec->xlen) &&
                             (NULL != spec->y && 0 < spec->ylen));
    if (!hasPriv && !hasPub)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    ec = EC_KEY_new_by_curve_name(spec->crv);
    if (NULL == ec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_EC_failed;
    }

    params = (EC_GROUP *)EC_KEY_get0_group(ec);
    if (NULL == params)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_EC_failed;
    }

    // convert d from octet string to BIGNUM
    if (hasPriv)
    {
        bnD = BN_bin2bn(spec->d, spec->dlen, NULL);
        if (NULL == bnD)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }
        if (1 != EC_KEY_set_private_key(ec, bnD))
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            goto create_EC_failed;
        }

        // calculate public key from private
        Q = EC_POINT_new(params);
        if (NULL == Q)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }
        if (1 != EC_POINT_mul(params, Q, bnD, NULL, NULL, NULL))
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }

        // public key is set below
        // ignore provided public key!
        hasPub = false;
    }
    if (hasPub)
    {
        Q = EC_POINT_new(params);
        if (NULL == Q)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }

        bnX = BN_bin2bn(spec->x, spec->xlen, NULL);
        bnY = BN_bin2bn(spec->y, spec->ylen, NULL);
        if (!bnX || !bnY)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }

        if (1 != EC_POINT_set_affine_coordinates_GFp(params, Q, bnX, bnY, NULL))
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }
    }

    // always set the public key
    if (1 != EC_KEY_set_public_key(ec, Q))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_EC_failed;
    }
    
    jwk = _EC_new(spec->crv, ec, err);
    if (!jwk)
    {
        goto create_EC_failed;
    }

    // jump to cleanup
    goto create_EC_cleanup;

    create_EC_failed:
    if (jwk)
    {
        free(jwk);
        jwk = NULL;
    }
    if (ec)
    {
        EC_KEY_free(ec);
        ec = NULL;
    }

    create_EC_cleanup:
    if (Q)
    {
        EC_POINT_free(Q);
        Q = NULL;
    }
    if (bnD)
    {
        BN_free(bnD);
        bnD = NULL;
    }
    if (bnX)
    {
        BN_free(bnX);
        bnX = NULL;
    }
    if (bnY)
    {
        BN_free(bnY);
        bnY = NULL;
    }

    return jwk;
}

//////////////// RSA ////////////////
// internal data & functions -- RSA

static void _RSA_free(cjose_jwk_t *jwk);
static bool _RSA_public_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _RSA_private_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable RSA_FNTABLE = {
    _RSA_free,
    _RSA_public_fields,
    _RSA_private_fields
};

static inline cjose_jwk_t *_RSA_new(RSA *rsa, cjose_err *err)
{
    cjose_jwk_t *jwk = malloc(sizeof(cjose_jwk_t));
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memset(jwk, 0, sizeof(cjose_jwk_t));
    jwk->retained = 1;
    jwk->kty = CJOSE_JWK_KTY_RSA;
    jwk->keysize = RSA_size(rsa) * 8;
    jwk->keydata = rsa;
    jwk->fns = &RSA_FNTABLE;

    return jwk;
}

static void _RSA_free(cjose_jwk_t *jwk)
{
    RSA *rsa = (RSA *)jwk->keydata;
    jwk->keydata = NULL;
    if (rsa)
    {
        RSA_free(rsa);
    }
    free(jwk);
}

static inline bool _RSA_json_field(
        BIGNUM *param, const char *name, json_t *json, cjose_err *err)
{
    json_t      *field = NULL;
    uint8_t     *data = NULL;
    char        *b64u = NULL;
    size_t      datalen = 0,
                b64ulen = 0;
    bool        result = false;

    if (!param)
    {
        return true;
    }

    datalen = BN_num_bytes(param);
    data = malloc(sizeof(uint8_t) * datalen);
    if (!data)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto RSA_json_field_cleanup;
    }
    BN_bn2bin(param, data);
    if (!cjose_base64url_encode(data, datalen, &b64u, &b64ulen, err))
    {
        goto RSA_json_field_cleanup;
    }
    field = json_stringn(b64u, b64ulen);
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto RSA_json_field_cleanup;
    }
    json_object_set(json, name, field);
    json_decref(field);
    field = NULL;
    result = true;

    RSA_json_field_cleanup:
    if (b64u)
    {
        free(b64u);
        b64u = NULL;
    }
    if (data)
    {
        free(data);
        data = NULL;
    }

    return result;
}

static bool _RSA_public_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    RSA *rsa = (RSA *)jwk->keydata;
    if (!_RSA_json_field(rsa->e, "e", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa->n, "n", json, err))
    {
        return false;
    }

    return true;
}

static bool _RSA_private_fields(
        const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    RSA *rsa = (RSA *)jwk->keydata;
    if (!_RSA_json_field(rsa->d, "d", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa->p, "p", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa->q, "q", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa->dmp1, "dp", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa->dmq1, "dq", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa->iqmp, "qi", json, err))
    {
        return false;
    }

    return true;
}

// interface functions -- RSA
static const uint8_t *DEFAULT_E_DAT = (const uint8_t *)"\x01\x00\x01";
static const size_t DEFAULT_E_LEN = 3;

cjose_jwk_t *cjose_jwk_create_RSA_random(
        size_t keysize, const uint8_t *e, size_t elen, cjose_err *err)
{
    if (0 == keysize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }
    if (NULL == e || 0 >= elen)
    {
        e = DEFAULT_E_DAT;
        elen = DEFAULT_E_LEN;
    }

    RSA     *rsa = NULL;
    BIGNUM  *bn = NULL;

    rsa = RSA_new();
    if (!rsa)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_random_failed;
    }

    bn = BN_bin2bn(e, elen, NULL);
    if (!bn)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_random_failed;
    }

    if (0 == RSA_generate_key_ex(rsa, keysize, bn, NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_random_failed;
    }

    return _RSA_new(rsa, err);

    create_RSA_random_failed:
    if (bn)
    {
        BN_free(bn);
    }
    if (rsa)
    {
        RSA_free(rsa);
    }
    return NULL;
}

static inline bool _RSA_set_param(
        BIGNUM **param, const uint8_t *data, size_t len, cjose_err *err)
{
    BIGNUM  *bn = NULL;
    if (NULL != data && 0 < len)
    {
        bn = BN_bin2bn(data, len, NULL);
        if (!bn)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            return false;
        }
        *param = bn;
    }

    return true;
}

cjose_jwk_t *cjose_jwk_create_RSA_spec(
        const cjose_jwk_rsa_keyspec *spec, cjose_err *err)
{
    if (NULL == spec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    bool        hasPub = (NULL != spec->n && 0 < spec->nlen) &&
                         (NULL != spec->e && 0 < spec->elen);
    bool        hasPriv = (NULL != spec->n && 0 < spec->nlen) &&
                          (NULL != spec->d && 0 < spec->dlen);
    if (!hasPub && !hasPriv)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    RSA     *rsa = NULL;
    rsa = RSA_new();
    if (!rsa)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }

    if (hasPriv)
    {
        if (!_RSA_set_param(&rsa->n, spec->n, spec->nlen, err))
        {
            goto create_RSA_spec_failed;
        }
        if (!_RSA_set_param(&rsa->d, spec->d, spec->dlen, err))
        {
            goto create_RSA_spec_failed;
        }
        if (!_RSA_set_param(&rsa->p, spec->p, spec->plen, err))
        {
            goto create_RSA_spec_failed;
        }
        if (!_RSA_set_param(&rsa->q, spec->q, spec->qlen, err))
        {
            goto create_RSA_spec_failed;
        }
        if (!_RSA_set_param(&rsa->dmp1, spec->dp, spec->dplen, err))
        {
            goto create_RSA_spec_failed;
        }
        if (!_RSA_set_param(&rsa->dmq1, spec->dq, spec->dqlen, err))
        {
            goto create_RSA_spec_failed;
        }
        if (!_RSA_set_param(&rsa->iqmp, spec->qi, spec->qilen, err))
        {
            goto create_RSA_spec_failed;
        }
    }
    if (hasPub)
    {
        if (!_RSA_set_param(&rsa->e, spec->e, spec->elen, err))
        {
            goto create_RSA_spec_failed;
        }
        if (!hasPriv && !_RSA_set_param(&rsa->n, spec->n, spec->nlen, err))
        {
            goto create_RSA_spec_failed;
        }
    }

    return _RSA_new(rsa, err);

    create_RSA_spec_failed:
    if (rsa)
    {
        RSA_free(rsa);
    }

    return NULL;
}

//////////////// Import ////////////////
// internal data & functions -- JWK key import


static const char *_get_json_object_string_attribute(
        json_t *json, const char *key, cjose_err *err)
{
    const char  *attr_str = NULL;
    json_t *attr_json = json_object_get(json, key);
    if (NULL != attr_json)
    {
        attr_str = json_string_value(attr_json);
    }
    return attr_str;
} 


/**
 * Internal helper function for extracing an octet string from a base64url
 * encoded field.  Caller provides the json object, the attribute key,
 * and an expected length for the octet string.  On successful decoding,
 * this will return a newly allocated buffer with the decoded octet string
 * of the expected length.
 *
 * Note: caller is responsible for freeing the buffer returned by this function.
 *
 * \param[in]     json the JSON object from which to read the attribute.
 * \param[in]     key the name of the attribute to be decoded.
 * \param[out]    pointer to buffer of octet string (if decoding succeeds).
 * \param[in/out] in as the expected length of the attribute, out as the 
 *                actual decoded length.  Note, this method succeeds only
 *                if the actual decoded length matches the expected length.
 *                If the in-value is 0 this indicates there is no particular
 *                expected length (i.e. any length is ok).
 * \returns true  if attribute is either not present or successfully decoded.
 *                false otherwise.
 */
static bool _decode_json_object_base64url_attribute(json_t *jwk_json, 
        const char *key, uint8_t **buffer, size_t *buflen, cjose_err *err)
{
    // get the base64url encoded string value of the attribute (if any)
    const char *str = _get_json_object_string_attribute(jwk_json, key, err);
    if (str == NULL || strlen(str) == 0)
    {
        *buflen = 0;
        *buffer = NULL;
        return true;
    }

    // if a particular decoded length is expected, check for that
    if (*buflen != 0)
    {
        const char *end = NULL;
        for (end = str + strlen(str) - 1; *end == '=' && end > str; --end);
        size_t unpadded_len = end + 1 - str - ((*end == '=') ? 1 : 0);
        size_t expected_len = ceil(4 * ((float)*buflen / 3));

        if (expected_len != unpadded_len)
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            *buflen = 0;
            *buffer = NULL;
            return false;
        }
    }

    // decode the base64url encoded string to the allocated buffer
    if (!cjose_base64url_decode(str, strlen(str), buffer, buflen, err))
    {
        *buflen = 0;
        *buffer = NULL;
        return false;
    }

    return true;
}

static cjose_jwk_t *_cjose_jwk_import_EC(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *x_buffer = NULL;
    uint8_t *y_buffer = NULL;
    uint8_t *d_buffer = NULL;

    // get the value of the crv attribute
    const char *crv_str = 
            _get_json_object_string_attribute(jwk_json, CJOSE_JWK_CRV_STR, err);
    if (crv_str == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }
 
    // get the curve identifer for the curve named by crv
    cjose_jwk_ec_curve crv;
    if (!_ec_curve_from_name(crv_str, &crv, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    } 

    // get the decoded value of the x coordinate
    size_t x_buflen = (size_t)_ec_size_for_curve(crv, err);
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_X_STR, &x_buffer, &x_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the decoded value of the y coordinate
    size_t y_buflen = (size_t)_ec_size_for_curve(crv, err);
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_Y_STR,  &y_buffer, &y_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the decoded value of the private key d
    size_t d_buflen = (size_t)_ec_size_for_curve(crv, err);
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_D_STR,  &d_buffer, &d_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // create an ec keyspec
    cjose_jwk_ec_keyspec ec_keyspec;
    memset(&ec_keyspec, 0, sizeof(cjose_jwk_ec_keyspec));
    ec_keyspec.crv = crv;
    ec_keyspec.x = x_buffer;
    ec_keyspec.xlen = x_buflen;
    ec_keyspec.y = y_buffer;
    ec_keyspec.ylen = y_buflen;
    ec_keyspec.d = d_buffer;
    ec_keyspec.dlen = d_buflen;

    // create the jwk
    jwk = cjose_jwk_create_EC_spec(&ec_keyspec, err);

    import_EC_cleanup:
    if (NULL != x_buffer)
    {
        free(x_buffer);
    }
    if (NULL != y_buffer)
    {
        free(y_buffer);
    }
    if (NULL != d_buffer)
    {
        free(d_buffer);
    }

    return jwk;
}

static cjose_jwk_t *_cjose_jwk_import_RSA(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *n_buffer = NULL;
    uint8_t *e_buffer = NULL;
    uint8_t *d_buffer = NULL;
    uint8_t *p_buffer = NULL;
    uint8_t *q_buffer = NULL;
    uint8_t *dp_buffer = NULL;
    uint8_t *dq_buffer = NULL;
    uint8_t *qi_buffer = NULL;

    // get the decoded value of n (buflen = 0 means no particular expected len) 
    size_t n_buflen = 0;
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_N_STR, &n_buffer, &n_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of e 
    size_t e_buflen = 0;
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_E_STR, &e_buffer, &e_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of d 
    size_t d_buflen = 0;
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_D_STR, &d_buffer, &d_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of p 
    size_t p_buflen = 0;
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_P_STR, &p_buffer, &p_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of q 
    size_t q_buflen = 0;
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_Q_STR, &q_buffer, &q_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of dp 
    size_t dp_buflen = 0;
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_DP_STR, &dp_buffer, &dp_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of dq 
    size_t dq_buflen = 0;
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_DQ_STR, &dq_buffer, &dq_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of qi 
    size_t qi_buflen = 0;
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_QI_STR, &qi_buffer, &qi_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // create an rsa keyspec
    cjose_jwk_rsa_keyspec rsa_keyspec;
    memset(&rsa_keyspec, 0, sizeof(cjose_jwk_rsa_keyspec));
    rsa_keyspec.n = n_buffer;
    rsa_keyspec.nlen = n_buflen;
    rsa_keyspec.e = e_buffer;
    rsa_keyspec.elen = e_buflen;
    rsa_keyspec.d = d_buffer;
    rsa_keyspec.dlen = d_buflen;
    rsa_keyspec.p = p_buffer;
    rsa_keyspec.plen = p_buflen;
    rsa_keyspec.q = q_buffer;
    rsa_keyspec.qlen = q_buflen;
    rsa_keyspec.dp = dp_buffer;
    rsa_keyspec.dplen = dp_buflen;
    rsa_keyspec.dq = dq_buffer;
    rsa_keyspec.dqlen = dq_buflen;
    rsa_keyspec.qi = qi_buffer;
    rsa_keyspec.qilen = qi_buflen;

    // create the jwk
    jwk = cjose_jwk_create_RSA_spec(&rsa_keyspec, err);

    import_RSA_cleanup:
    free(n_buffer);
    free(e_buffer);
    free(d_buffer);
    free(p_buffer);
    free(q_buffer);
    free(dp_buffer);
    free(dq_buffer);
    free(qi_buffer);

    return jwk;
}

static cjose_jwk_t *_cjose_jwk_import_oct(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *k_buffer = NULL;

    // get the decoded value of k (buflen = 0 means no particular expected len) 
    size_t k_buflen = 0;
    if (!_decode_json_object_base64url_attribute(
            jwk_json, CJOSE_JWK_K_STR, &k_buffer, &k_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_oct_cleanup;
    }

    // create the jwk
    jwk = cjose_jwk_create_oct_spec(k_buffer, k_buflen, err);

    import_oct_cleanup:
    if (NULL != k_buffer)
    {
        free(k_buffer);
    }

    return jwk;
}

cjose_jwk_t *cjose_jwk_import(const char *jwk_str, size_t len, cjose_err *err) 
{
    cjose_jwk_t *jwk= NULL;

    // check params
    if ((NULL == jwk_str) || (0 == len))
    {
        return NULL;
    }

    // parse json content from the given string
    json_t *jwk_json = json_loadb(jwk_str, len, 0, NULL);
    if (NULL == jwk_json)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_cleanup;
    }

    // get the string value of the kty attribute of the jwk
    const char *kty_str = 
            _get_json_object_string_attribute(jwk_json, CJOSE_JWK_KTY_STR, err);
    if (NULL == kty_str)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_cleanup;
    } 

    // get kty cooresponding to kty_str (kty is required)
    cjose_jwk_kty_t kty;
    if (!_kty_from_name(kty_str, &kty, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_cleanup;
    }
  
    // create a cjose_jwt_t based on the kty
    switch (kty)
    {
        case CJOSE_JWK_KTY_EC:  
            jwk = _cjose_jwk_import_EC(jwk_json, err);
            break;

        case CJOSE_JWK_KTY_RSA:  
            jwk = _cjose_jwk_import_RSA(jwk_json, err);
            break;

        case CJOSE_JWK_KTY_OCT:  
            jwk = _cjose_jwk_import_oct(jwk_json, err);
            break;

        default:
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            goto import_cleanup;
    }
    if (NULL == jwk)
    {
        // helper function will have already set err
        goto import_cleanup;
    }

    // get the value of the kid attribute (kid is optional)
    const char *kid_str = 
            _get_json_object_string_attribute(jwk_json, CJOSE_JWK_KID_STR, err);
    if (kid_str != NULL)
    {
        jwk->kid = strdup(kid_str);
    } 

    // poor man's "finally"
    import_cleanup:
    if (NULL != jwk_json)
    {
        json_decref(jwk_json);
    }

    return jwk;
}

//////////////// ECDH ////////////////
// internal data & functions -- ECDH derivation

static bool _cjose_jwk_evp_key_from_ec_key(
        cjose_jwk_t *jwk, EVP_PKEY **key, cjose_err *err)
{
    // validate that the jwk is of type EC and we have a valid out-param
    if (NULL == jwk || 
            CJOSE_JWK_KTY_EC != jwk->kty || 
            NULL == jwk->keydata ||
            NULL == key ||
            NULL != *key)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jwk_evp_key_from_ec_key_fail;        
    }

    // create a blank EVP_PKEY
    *key = EVP_PKEY_new();
    if (NULL == key)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_evp_key_from_ec_key_fail;
    }

    // assign the EVP_PKEY to reference the jwk's internal EC_KEY structure
    if (1 != EVP_PKEY_set1_EC_KEY(
            *key, ((struct _ec_keydata_int *)(jwk->keydata))->key))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_evp_key_from_ec_key_fail;
    }

    // happy path
    return true;

    // fail path
    _cjose_jwk_evp_key_from_ec_key_fail:

    EVP_PKEY_free(*key);
    *key = NULL;

    return false;
}


cjose_jwk_t *cjose_jwk_derive_ecdh_secret(
        cjose_jwk_t *jwk_self,
        cjose_jwk_t *jwk_peer,
        cjose_err *err)
{
    return cjose_jwk_derive_ecdh_ephemeral_key(jwk_self, jwk_peer, err);
}


cjose_jwk_t *cjose_jwk_derive_ecdh_ephemeral_key(
        cjose_jwk_t *jwk_self,
        cjose_jwk_t *jwk_peer,
        cjose_err *err) 
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey_self = NULL;
    EVP_PKEY *pkey_peer = NULL;
    uint8_t *secret = NULL;
    size_t secret_len = 0;
    uint8_t *ephemeral_key = NULL;
    size_t ephemeral_key_len = 0;
    cjose_jwk_t *jwk_ephemeral_key = NULL;

    // get EVP_KEY from jwk_self
    if (!_cjose_jwk_evp_key_from_ec_key(jwk_self, &pkey_self, err))
    {
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // get EVP_KEY from jwk_peer
    if (!_cjose_jwk_evp_key_from_ec_key(jwk_peer, &pkey_peer, err))
    {
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // create derivation context based on local key pair
    ctx = EVP_PKEY_CTX_new(pkey_self, NULL);
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // initialize derivation context
    if (1 != EVP_PKEY_derive_init(ctx))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // provide the peer public key
    if (1 != EVP_PKEY_derive_set_peer(ctx, pkey_peer))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // determine buffer length for shared secret
    if(1 != EVP_PKEY_derive(ctx, NULL, &secret_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // allocate buffer for shared secret
    secret = (uint8_t *)malloc(secret_len);
    if (NULL == secret)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jwk_derive_shared_secret_fail;        
    }
    memset(secret, 0, secret_len);

    // derive the shared secret
    if (1 != (EVP_PKEY_derive(ctx, secret, &secret_len)))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jwk_derive_shared_secret_fail;                
    }

    // HKDF of the DH shared secret (SHA256, no salt, no info, 256 bit expand)
    ephemeral_key_len = 32;
    ephemeral_key = (uint8_t *)malloc(ephemeral_key_len);
    if (!cjose_jwk_hkdf(EVP_sha256(), (uint8_t *)"", 0, (uint8_t *)"", 0, 
            secret, secret_len, ephemeral_key, ephemeral_key_len, err))
    {
        goto _cjose_jwk_derive_shared_secret_fail;        
    }

    // create a JWK of the shared secret
    jwk_ephemeral_key = cjose_jwk_create_oct_spec(
            ephemeral_key, ephemeral_key_len, err);
    if (NULL == jwk_ephemeral_key)
    {
        goto _cjose_jwk_derive_shared_secret_fail;        
    }

    // happy path
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey_self);
    EVP_PKEY_free(pkey_peer);
    free(secret);
    free(ephemeral_key);

    return jwk_ephemeral_key;

    // fail path
    _cjose_jwk_derive_shared_secret_fail:
    
    if (NULL != ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }
    if (NULL != pkey_self)
    {
        EVP_PKEY_free(pkey_self);
    }
    if (NULL != pkey_peer)
    {
        EVP_PKEY_free(pkey_peer);
    }
    if (NULL != jwk_ephemeral_key)
    {
        cjose_jwk_release(jwk_ephemeral_key);
    }
    free(secret);
    free(ephemeral_key);
    return NULL;
}

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
        cjose_err *err)
{
    // current impl. is very limited: SHA256, 256 bit output, and no info
    if ((EVP_sha256() != md) || (0 != info_len) || (32 != okm_len)) {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // HKDF-Extract, HMAC-SHA256(salt, IKM) -> PRK
    unsigned int prk_len;
    unsigned char prk[EVP_MAX_MD_SIZE];
    HMAC(md, salt, salt_len, ikm, ikm_len, prk, &prk_len);
 
    // HKDF-Expand, HMAC-SHA256(PRK,0x01) -> OKM
    const unsigned char t[] = { 0x01 };
    HMAC(md, prk, prk_len, t, sizeof(t), okm, NULL);

    return true;
}
