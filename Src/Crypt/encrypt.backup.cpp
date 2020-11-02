#include "header.h"

std::string sfy(const NTSTATUS nts)
{
	std::stringstream ss;
	ss << "NTSTATUS=" << std::hex << nts;
	return ss.str();
}

bool encrypt(PBYTE data, DWORD dataSize, PBYTE pwd, DWORD pwdSize)
{
//#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
//#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

	BCRYPT_ALG_HANDLE       hAlg = NULL;
	BCRYPT_KEY_HANDLE       hKey = NULL;
	NTSTATUS                status = 0;
	DWORD
		cbData = 0,		//how many bytes written
		cbKeyObject = 0,//key size
		cbBlockLen = 0,	//iv size
		cbBlob = 0;		//stored key size
	PBYTE
		pbKeyObject = NULL,	//key
		pbIV = NULL,		//iv
		pbIV_org = nullptr, //iv
		pbBlob = NULL;		//key stored to memory

	/*PBYTE
		hash = nullptr;*/
	size_t hashSize = 32;
	std::vector<BYTE> hash(hashSize);

	try 
	{
		std::cout << data << "\n";
		/****************************
		Password hash
		*****************************/

		//allocate hash
		/*hash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, hashSize);
		if (!hash) {
			throw std::runtime_error("hash allocation");
		}*/

		//create hash from password
		if (!NT_SUCCESS(status = BCryptHash(
			BCRYPT_SHA256_ALG_HANDLE,
			NULL,
			0,
			pwd,
			pwdSize,
			(PUCHAR)&hash[0],
			hashSize)))
		{
			throw std::runtime_error("hash creation");
		}
		
		/**************************
		Algorithm handle
		**************************/

		//open an algorithm handle
		//or use global BCRYPT_AES_CCM_ALG_HANDLE
		if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
			&hAlg,
			BCRYPT_AES_ALGORITHM,
			NULL,
			0)))
		{
			throw std::runtime_error("BCryptOpenAlgorithmProvider: " + status);
		}

		//set properties
		if (!NT_SUCCESS(status = BCryptSetProperty(
			hAlg,
			BCRYPT_CHAINING_MODE,
			(PBYTE)BCRYPT_CHAIN_MODE_CCM,
			sizeof(BCRYPT_CHAIN_MODE_CCM),
			0)))
		{
			throw std::runtime_error("BCryptSetProperty: " + status);
		}

		/*****************************
		Key
		******************************/

		//calculate KeyObject size
		if (!NT_SUCCESS(status = BCryptGetProperty(
			hAlg,
			BCRYPT_OBJECT_LENGTH,
			(PBYTE)&cbKeyObject,
			sizeof(DWORD),
			&cbData,
			0)))
		{
			throw std::runtime_error("BCryptGetProperty: " + status);
		}

		//allocate KeyObject
		pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
		if (NULL == pbKeyObject)
		{
			throw std::runtime_error("keyobject memory allocation failed");
		}

		//create Key from password hash.
		if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
			hAlg,
			&hKey,
			pbKeyObject,
			cbKeyObject,
			(PUCHAR)&hash[0],
			hashSize,
			0)))
		{
			throw std::runtime_error("BCryptGenerateSymmetricKey: " + status);
		}

		//calculate keyObject size for export
		if (!NT_SUCCESS(status = BCryptExportKey(
			hKey,
			NULL,
			BCRYPT_OPAQUE_KEY_BLOB,
			NULL,
			0,
			&cbBlob,
			0)))
		{
			throw std::runtime_error("BCryptExportKey: " + status);
		}

		// Allocate blob
		pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
		if (NULL == pbBlob)
		{
			throw std::runtime_error("blob memory allocation failed");
		}

		//export key to blob
		if (!NT_SUCCESS(status = BCryptExportKey(
			hKey,
			NULL,
			BCRYPT_OPAQUE_KEY_BLOB,
			pbBlob,
			cbBlob,
			&cbBlob,
			0)))
		{
			throw std::runtime_error("BCryptExportKey: " + status);
		}

		/******************************
		IV
		******************************/

		// Calculate the block length for the IV.
		if (!NT_SUCCESS(status = BCryptGetProperty(
			hAlg,
			BCRYPT_BLOCK_LENGTH,
			(PBYTE)&cbBlockLen,
			sizeof(DWORD),
			&cbData,
			0)))
		{
			throw std::runtime_error("BCryptGetProperty: " + status);
		}

		// Allocate a buffer for the IV.
		std::vector<BYTE> IV(cbBlockLen);

		//create IV
		if (!NT_SUCCESS(status = BCryptGenRandom(
			BCRYPT_RNG_ALG_HANDLE,
			&IV[0],
			cbBlockLen,
			0)))
		{
			throw std::runtime_error("iv creation: " + status);
		}

		/**************************************
		Tags
		***************************************/
		BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;
		if (!NT_SUCCESS(status = BCryptGetProperty(
			hAlg, 
			BCRYPT_AUTH_TAG_LENGTH, 
			(BYTE*)&authTagLengths, 
			sizeof(authTagLengths), 
			&cbData, 
			0)))
		{
			throw std::runtime_error("auth tag length");
		}

		/***************************************
		Cipher info
		***************************************/

		std::vector<BYTE> authTag(authTagLengths.dwMinLength);
		const size_t GCM_NONCE_SIZE = 12;

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO acmi;
		BCRYPT_INIT_AUTH_MODE_INFO(acmi);
		acmi.pbNonce = &IV[0];
		acmi.cbNonce = GCM_NONCE_SIZE;
		acmi.pbTag = &authTag[0];
		acmi.cbTag = authTag.size();

		/***************************************
		Encryption
		****************************************/

		//encrypt text buffer with key
		if (!NT_SUCCESS(status = BCryptEncrypt(
			hKey,
			data,
			dataSize,
			&acmi,
			NULL,
			0,
			data,
			dataSize,
			&cbData,
			0)))
		{
			throw std::runtime_error("BCryptEncrypt: " + sfy(status));
		}

		//destroy the key
		if (!NT_SUCCESS(status = BCryptDestroyKey(hKey)))
		{
			throw std::runtime_error("BCryptDestroyKey: " + status);
		}
		hKey = 0;
		memset(pbKeyObject, 0, cbKeyObject);

		//print result
		std::cout << data << "\n";

		/************************************
		decryption
		************************************/


		//import key
		if (!NT_SUCCESS(status = BCryptImportKey(
			hAlg,
			NULL,
			BCRYPT_OPAQUE_KEY_BLOB,
			&hKey,
			pbKeyObject,
			cbKeyObject,
			pbBlob,
			cbBlob,
			0)))
		{
			throw std::runtime_error("BCryptGenerateSymmetricKey: " + status);
		}

		if (!NT_SUCCESS(status = BCryptDecrypt(
			hKey,
			data,
			dataSize,
			&acmi,
			NULL,
			0,
			data,
			dataSize,
			&cbData,
			0)))
		{
			throw std::runtime_error("BCryptDecrypt: " + status);
		}

		//print result
		std::cout << data << "\n";
	}
	catch (const std::exception& e)
	{
		brb::err("encryption failed", e.what());
		return false;
	}

	if (hAlg) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}

	if (hKey) {
		BCryptDestroyKey(hKey);
	}

	if (pbKeyObject) {
		HeapFree(GetProcessHeap(), 0, pbKeyObject);
	}

	if (pbIV) {
		HeapFree(GetProcessHeap(), 0, pbIV);
	}
	return true;
}