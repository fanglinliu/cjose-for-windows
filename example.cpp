#include "cjose/cjose.h"
#include <string>
using namespace std;

// generated a AES-256-GCM key
string generateAES256GCMKey()
{
	cjose_err err;
	err.code = CJOSE_ERR_NONE;

	const char *cstrJwkContentKey = NULL;

	cjose_jwk_t *jwkContentKey = NULL;

	// generate 256 bit random
	if (CJOSE_ERR_NONE == err.code)
	{
		jwkContentKey = cjose_jwk_create_oct_random(256, &err);
	}

	// set return value
	if (CJOSE_ERR_NONE == err.code)
	{
		
		//cstrJwkContentKey = reinterpret_cast<const char *> (jwkContentKey->keydata);
	}

	return cstrJwkContentKey;
}

// decrypt content from ciphertext
string contentFromCiphertext(string ciphertext, string key)
{
	string plaintext = NULL;

	cjose_err err;
	err.code = CJOSE_ERR_NONE;

	const char *cstrJwkContentKey = key.c_str();
	const char *cstrJweContent = ciphertext.c_str();

	// check input
	if (ciphertext.empty() || key.empty() )
	{
		err.code = CJOSE_ERR_INVALID_ARG;
	}

	// import jwk
	cjose_jwk_t *jwkContentKey = NULL;
	if (CJOSE_ERR_NONE == err.code)
	{
		jwkContentKey = cjose_jwk_import(cstrJwkContentKey, strlen(cstrJwkContentKey), &err);
	}

	// import jwe
	cjose_jwe_t *jweContent = NULL;
	if (CJOSE_ERR_NONE == err.code)
	{
		jweContent = cjose_jwe_import(cstrJweContent, strlen(cstrJweContent), &err);
	}

	// decrypt the imported jwe
	uint8_t *cstrContent = NULL;
	size_t cstrContentLen = 0;
	if (CJOSE_ERR_NONE == err.code)
	{
		cstrContent = cjose_jwe_decrypt(jweContent, jwkContentKey, &cstrContentLen, &err);
	}

	// cleanup
	cjose_jwk_release(jwkContentKey);
	cjose_jwe_release(jweContent);

	// set return value
	if (CJOSE_ERR_NONE == err.code)
	{
		plaintext = (char*)cstrContent;
	}

	return plaintext;
}