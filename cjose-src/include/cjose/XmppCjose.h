#include <string>
#include "cjose/cjose.h"

#ifdef __cplusplus
extern "C"
{
#endif
#define DEFAULT_KEYSIZE 256

class CXmppCjose
{
public:
	CXmppCjose();
	~CXmppCjose();

	bool GenerateBase64urlAESKey(std::string& base64urlKey);
	bool DecryptCiphertext(std::string ciphertext, std::string key, std::string& plaintext);

private:
	cjose_jwk_t *m_jwkContentKey;
	cjose_jwe_t *m_jweContent;
};



#ifdef __cplusplus
}
#endif