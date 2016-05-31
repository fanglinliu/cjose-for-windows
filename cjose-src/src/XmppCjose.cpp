
//#include "stdafx.h"
#include "cjose/XmppCjose.h"


CXmppCjose::CXmppCjose()
{
	m_jwkContentKey = NULL;
	m_jweContent = NULL;
}

CXmppCjose::~CXmppCjose()
{
	cjose_jwk_release(m_jwkContentKey);
	cjose_jwe_release(m_jweContent);
}

bool CXmppCjose::GenerateBase64urlAESKey(std::string& base64urlKey)
{
//#ifdef AT_IOS
	cjose_err err;
	err.code = CJOSE_ERR_NONE;

	// generate 256 bit random
	m_jwkContentKey = cjose_jwk_create_oct_random(DEFAULT_KEYSIZE, &err);

	if (CJOSE_ERR_NONE != err.code)
	{
		//xmppsdk_info0 << _T("cjose generate random error: ") << AT_A2T(err.message);
		return false;
	}

	uint8_t *keyData = NULL;
	keyData = (uint8_t *)cjose_jwk_get_keydata(m_jwkContentKey, &err);

	if (CJOSE_ERR_NONE != err.code)
	{
		//xmppsdk_info0 << _T("cjose get keydata error: ") << AT_A2T(err.message);
		return false;
	}

	size_t keySize = NULL;
	keySize = cjose_jwk_get_keysize(m_jwkContentKey, &err);

	if (CJOSE_ERR_NONE != err.code)
	{
		//xmppsdk_info0 << _T("cjose get keysize error: ") << AT_A2T(err.message);
		return false;
	}

	size_t keyLen = 0;
	bool encoded = false;
	const char *cstrJwkContentKey = NULL;
	// keyData is a 'uint8_t *' of length (keySize / 8)
	encoded = cjose_base64url_encode(keyData, keySize / 8, (char **)&cstrJwkContentKey, &keyLen, &err);

	// set return value
	if (encoded && CJOSE_ERR_NONE == err.code)
	{
		base64urlKey = std::string(cstrJwkContentKey, keyLen);
		return true;
	}
	else
	{
		//xmppsdk_info0 << _T("cjose base64url encode error: ") << AT_A2T(err.message);
		return false;
	}

//#else
//	return false;
//#endif
}

bool CXmppCjose::DecryptCiphertext(std::string ciphertext, std::string key, std::string& plaintext)
{
//#ifdef AT_IOS
	if (ciphertext.empty() || key.empty())
	{
		//xmppsdk_info0 << _T("input parameters invalid");
		return false;
	}

	cjose_err err;
	err.code = CJOSE_ERR_NONE;
	bool decoded = false;
	const char *cstrJwkContentKey = NULL;
	size_t keyLen = 0;
	decoded = cjose_base64url_decode(key.c_str(), key.size(), (uint8_t **)&cstrJwkContentKey, &keyLen, &err);

	if (!decoded || CJOSE_ERR_NONE != err.code)
	{
		//xmppsdk_info0 << _T("cjose base64url decode error: ") << AT_A2T(err.message);
		return false;
	}

	// create jwk
	m_jwkContentKey = cjose_jwk_create_oct_spec((uint8_t *)cstrJwkContentKey, keyLen, &err);

	if (CJOSE_ERR_NONE != err.code)
	{
		//xmppsdk_info0 << _T("cjose create jwk error: ") << AT_A2T(err.message);
		return false;
	}

	// import jwe
	const char *cstrJweContent = ciphertext.c_str();
	if (CJOSE_ERR_NONE == err.code)
	{
		m_jweContent = cjose_jwe_import(cstrJweContent, strlen(cstrJweContent), &err);
	}

	// decrypt the imported jwe
	uint8_t *cstrContent = NULL;
	size_t cstrContentLen = 0;
	cstrContent = cjose_jwe_decrypt(m_jweContent, m_jwkContentKey, &cstrContentLen, &err);

	// set return value
	if (CJOSE_ERR_NONE == err.code)
	{
		plaintext = std::string((char*)cstrContent, cstrContentLen);
		return true;
	}
	else
	{
		//xmppsdk_info0 << _T("cjose jwe decrypt ciphertext error: ") << AT_A2T(err.message);
		return false;
	}

//#else
//	return false;
//#endif
}