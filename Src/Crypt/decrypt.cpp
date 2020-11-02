#include "crypt.h"

bool Crypt::decrypt(PBYTE data, DWORD dataSize) {
	try 
	{
		/***************************************
		Retrieve key
		***************************************/
		if (!keyFromM() && !hKey) {
			throw std::runtime_error("No key found");
		}

		/***************************************
		Decryption
		****************************************/
		if (!NT_SUCCESS(status = BCryptDecrypt(
			hKey,
			data,
			dataSize,
			&acmi,
			NULL,
			0,
			data,
			dataSize,
			&bytesWritten,
			0)))
		{
			throw std::runtime_error("BCryptDecrypt: " + sfy(status));
		}

		/*******************************
		Delete key
		********************************/
		delKey();
	}
	catch (const std::runtime_error& e) {
		brb::err("decrypt", e.what());
		if (sfy(status).compare("NTSTATUS=c000a002") == 0) {
			brb::err("Error-code", "wrong password or file corrupted");
		}
		delKey();
		return false;
	}
	return true;
}


