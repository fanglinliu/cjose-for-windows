// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


#include "cjose/cjose.h"
#include <string>

using namespace std;

// generated a AES-256-GCM key
//string generateAES256GCMKey()
//{
//	cjose_err err;
//	err.code = CJOSE_ERR_NONE;
//
//	const char *cstrJwkContentKey = NULL;
//
//	cjose_jwk_t *jwkContentKey = NULL;
//
//	// generate 256 bit random
//	if (CJOSE_ERR_NONE == err.code)
//	{
//		jwkContentKey = cjose_jwk_create_oct_random(256, &err);
//	}
//
//	// set return value
//	// cjose to JSON
//	if (CJOSE_ERR_NONE == err.code)
//	{
//		//cstrJwkContentKey = jwkContentKey->keydata;
//	}
//
//	return cstrJwkContentKey;
////}

// decrypt content from ciphertext
string contentFromCiphertext(string ciphertext, string key)
{
	string plaintext = "";

	cjose_err err;
	err.code = CJOSE_ERR_NONE;

	const char *cstrJwkContentKey = key.c_str();
	const char *cstrJweContent = ciphertext.c_str();

	// check input
	// ciphertext.empty() key.empty()
	if (ciphertext.empty() || key.empty())
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
		plaintext = string((char*)cstrContent, cstrContentLen);
	}

	return plaintext;
}

string ciphertextFromContent(string content, string key)
{
	cjose_err err;
	err.code = CJOSE_ERR_NONE;

	string ciphertext = "";

	const uint8_t *octContent = (uint8_t *)content.c_str();
	const char * cstrJwkContentKey = key.c_str();

	// check inputs
	if (content.empty() || key.empty())
	{
		err.code = CJOSE_ERR_INVALID_ARG;
	}

	// import jwk
	cjose_jwk_t *jwkContentKey = NULL;
	if (CJOSE_ERR_NONE == err.code)
	{
		jwkContentKey = cjose_jwk_import(cstrJwkContentKey, strlen(cstrJwkContentKey), &err);
	}

	// create header for jwe
	cjose_header_t *hdr = NULL;
	if (CJOSE_ERR_NONE == err.code)
	{
		hdr = cjose_header_new(&err);
	}

	// use alg = dir
	if (CJOSE_ERR_NONE == err.code)
	{
		cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_DIR, &err);
	}

	// use enc = A256GCM
	if (CJOSE_ERR_NONE == err.code)
	{
		cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256GCM, &err);
	}

	// create jwe object
	cjose_jwe_t *jweContent = NULL;
	if (CJOSE_ERR_NONE == err.code)
	{
		size_t octContentLen = content.size();
		jweContent = cjose_jwe_encrypt(jwkContentKey, hdr, octContent, octContentLen, &err);
	}

	// export jwe as compact serialization
	char *strJweContent = NULL;
	if (CJOSE_ERR_NONE == err.code)
	{
		strJweContent = cjose_jwe_export(jweContent, &err);
	}

	// clean up
	cjose_jwk_release(jwkContentKey);
	cjose_header_release(hdr);
	cjose_jwe_release(jweContent);

	// set return value
	if (CJOSE_ERR_NONE == err.code)
	{
		ciphertext = strJweContent;
	}

	return ciphertext;
}

#include <fstream>
int main(int argc, char const *argv[])
{
//#include <iostream>
//#include <ctime>
//#include <fstream>
//#include <string>
//	using namespace std;
//
//
//	void main()
//	{
//		{
//			string name;
//			string rent;
//
//			ifstream infile;
//			infile.open("names.txt");
//			infile >> name >> rent;
	ifstream infile;
	infile.open("C:\\Users\\fangl\\Downloads\\cjose-for-windows-master\\cjose-for-windows-master\\json_string.txt");
	string AesKey = "";
	infile >> AesKey;
	string plaintext = "Hello world!";

	// encrypt
	string ciphertext = "";
	ciphertext = ciphertextFromContent(plaintext, AesKey);

	printf("%s\n", ciphertext.c_str());

	// decrypt
	string decryptContent = "";
	decryptContent = contentFromCiphertext(ciphertext, AesKey);

	printf("%s\n", decryptContent.c_str());

	return 0;
}


//int main()
//{
//    return 0;
//}

