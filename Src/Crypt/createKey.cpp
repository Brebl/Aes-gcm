#include "crypt.h"

bool Crypt::createKey()
{
	validity		val = validity::_null;

	try
	{
		{
			/****************************
				Password
			*****************************/
			/*
			No string:s to password because they are not safe
			(could be copied to somewere in memory)
			*/
			DWORD pwd_size = 0;
			wchar_t pwd[pwd_maxSize] = L"";
			while (val != validity::_valid) {
				askPwd(pwd, pwd_size, pwd_maxSize, val);
				val = validity::_valid;		//validation ignored here
			}

			/****************************
				Password hash
			*****************************/
			std::vector<BYTE> hash(hashSize);
			//create hash from password
			if (!NT_SUCCESS(status = BCryptHash(
				BCRYPT_SHA256_ALG_HANDLE,
				NULL,
				0,
				(PUCHAR)&pwd,
				pwd_size*sizeof(wchar_t),
				(PUCHAR)&hash[0],
				hashSize)))
			{
				SecureZeroMemory((PUCHAR)&pwd, pwd_size);
				SecureZeroMemory((PUCHAR)&hash[0], hashSize);
				throw std::runtime_error("hash creation: " + sfy(status));
			}

			/*****************************
				Key
			******************************/

			//create Key from password hash.
			if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
				hAlg,
				&hKey,
				(PUCHAR)&keyObj[0],
				cbKey,
				(PUCHAR)&hash[0],
				hashSize,
				0)))
			{
				delKey();
				throw std::runtime_error("BCryptGenerateSymmetricKey: " + sfy(status));
			}

			//delete pwd & hash
			SecureZeroMemory((PUCHAR)&pwd, pwd_size);
			SecureZeroMemory((PUCHAR)&hash[0], hashSize);
			return true;
		}
	}
	catch (const std::exception& e) {
		brb::log("createKey", e.what());
		return false;
	}
}