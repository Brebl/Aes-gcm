#include "crypt.h"

bool Crypt::encrypt(PBYTE data, DWORD dataSize)
{
	try 
	{
		/***************************************
		Retrieve key
		***************************************/
		if (!keyFromM() && !hKey) {
			throw std::runtime_error("No key found");
		}
		
		/***************************************
		Encryption
		****************************************/
		if (!NT_SUCCESS(status = BCryptEncrypt(
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
			throw std::runtime_error("BCryptEncrypt: " + sfy(status));
		}

		/*******************************
		Delete key
		********************************/
		delKey();
	}
	catch (const std::exception& e)
	{
		brb::err("Encryption failed", e.what());
		delKey();
		return false;
	}
	return true;
}