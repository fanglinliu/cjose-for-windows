/*
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

/**
 * \file
 * \brief
 * Functions and data structures for interacting with
 * JSON Web Signature (JWS) objects.
 *
 */

#ifndef CJOSE_HEADER_H
#define CJOSE_HEADER_H

#include <stdbool.h>
#include "cjose/error.h"

#ifdef __cplusplus
extern "C"
{
#endif


/** The JWE algorithm header attribute name. */
extern const char *CJOSE_HDR_ALG;

/** The JWE content encryption algorithm header attribute name. */
extern const char *CJOSE_HDR_ENC;

/** The JWE "cty" header attribute. */
extern const char *CJOSE_HDR_CTY;

/** The Jose "kid" header attribute. */
extern const char *CJOSE_HDR_KID;

/** The JWE algorithm attribute value for RSA-OAEP. */
extern const char *CJOSE_HDR_ALG_RSA_OAEP;

/** The JWE algorithm attribute value for PS256. */
extern const char *CJOSE_HDR_ALG_PS256;

/** The JWE algorithm attribute value for RS256. */
extern const char *CJOSE_HDR_ALG_RS256;

/** The JWE algorithm attribute value for "dir". */
extern const char *CJOSE_HDR_ALG_DIR;

/** The JWE content encryption algorithm value for A256GCM. */
extern const char *CJOSE_HDR_ENC_A256GCM;


/**
 * An instance of a header object (used when creating JWE/JWS objects).
 */
typedef struct json_t cjose_header_t;


/**
 * Instsantiates a new header object. Caller is responsible for
 * subsequently releasing the object through cjose_header_release().
 *
 * \param err [out] An optional error object which can be used to get additional
 *        information in the event of an error.
 * \returns a newly allocated header object, or NULL if an error occurs.
 */
cjose_header_t *cjose_header_new(
        cjose_err *err);


/**
 * Releases an existing header object. Callers must use this method
 * to dispose of header rather than directly free'ing a cjose_header
 * object.
 *
 * \param header[in] the header object to be released.
 */
void cjose_header_release(
		cjose_header_t *header);


/**
 * Sets a header attribute on a header object.  If that header was
 * previously set, this will replace the previous value with the new one.
 *
 * \param header[in] a previously instantated header object.
 * \param attr[in] the header attribute to be set.
 * \param value[in] the value to assign to the header attribute.
 * \param err [out] An optional error object which can be used to get additional
 *        information in the event of an error.
 * \returns true if header is successfully set.
 */
bool cjose_header_set(
        cjose_header_t *header,
        const char *attr,
        const char *value,
        cjose_err *err);

/**
 * Retrieves the value of the requested header attribute from the header
 * object.
 *
 * \param header[in] a header object.
 * \param attr[in] the header attribute to be got.
 * \param err [out] An optional error object which can be used to get additional
 *        information in the event of an error.
 * \returns a string containing the current value for the requested attribute.
 */
const char *cjose_header_get(
        cjose_header_t *header,
        const char *attr,
        cjose_err *err);


#ifdef __cplusplus
}
#endif

#endif  // CJOSE_HEADER_H
