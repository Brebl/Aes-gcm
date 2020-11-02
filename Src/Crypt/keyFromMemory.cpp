#include "crypt.h"

volatile bool Crypt::keyFromM()
{
	try {
		//import key
		if (!NT_SUCCESS(status = BCryptImportKey(
			hAlg,
			NULL,
			BCRYPT_KEY_DATA_BLOB,
			&hKey,
			(PUCHAR)&keyObj[0],
			cbKey,
			(PUCHAR)&pbBlob[0],
			cbBlob,
			0)))
		{
			throw std::runtime_error("BCryptImportKey: " + sfy(status));
		}
	}
	catch (const std::runtime_error& e) {
		brb::err("Key from memory", e.what());
		return false;
	}
	return true;
}