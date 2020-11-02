#include "crypt.h"

Crypt::Crypt()
{
	try {
		/**************************
		Algorithm handle
		**************************/

		//open an algorithm handle
		//or use global BCRYPT_AES_GCM_ALG_HANDLE
		if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
			&hAlg,
			BCRYPT_AES_ALGORITHM,
			NULL,
			0)))
		{
			throw std::runtime_error("BCryptOpenAlgorithmProvider: " + sfy(status));
		}

		//set properties
		if (!NT_SUCCESS(status = BCryptSetProperty(
			hAlg,
			BCRYPT_CHAINING_MODE,
			(PBYTE)BCRYPT_CHAIN_MODE_GCM,
			sizeof(BCRYPT_CHAIN_MODE_GCM),
			0)))
		{
			throw std::runtime_error("BCryptSetProperty: " + sfy(status));
		}

		/**************************************
		Nonce
		***************************************/
		if (!createNonce()) {
			throw std::runtime_error("Nonce creation failed");
		}

		/**************************************
		Tags
		***************************************/
		if (!NT_SUCCESS(status = BCryptGetProperty(
			hAlg,
			BCRYPT_AUTH_TAG_LENGTH,
			(BYTE*)&authTagLengths,
			sizeof(authTagLengths),
			&bytesWritten,
			0)))
		{
			throw std::runtime_error("auth tag length: " + sfy(status));
		}

		/***************************************
		Cipher info
		***************************************/

		authTag.assign(authTagLengths.dwMinLength,0);

		BCRYPT_INIT_AUTH_MODE_INFO(acmi);
		acmi.pbNonce = &nonce[0];
		acmi.cbNonce = gcmNonceSize;
		acmi.pbTag = &authTag[0];
		acmi.cbTag = authTag.size();

		/***************************************
		Key
		***************************************/
		// Calculate the size of the buffer to hold the KeyObject.
		if (!NT_SUCCESS(status = BCryptGetProperty(
			hAlg,
			BCRYPT_OBJECT_LENGTH,
			(PBYTE)&cbKey,
			sizeof(DWORD),
			&bytesWritten,
			0)))
		{
			throw std::runtime_error("keyobject size calculation: " + sfy(status));
		}

		// Allocate the key object
		keyObj.assign(cbKey, 0);

		if (!keyToM()) {
			delKey();
			throw std::runtime_error("key storing failed");
		}
	}
	catch (const std::exception& e) {
		brb::err("Crypt constructor", e.what());
	}
}