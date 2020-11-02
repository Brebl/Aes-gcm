#include "crypt.h"

volatile bool Crypt::keyToM()
{
	try 
	{
		if (!createKey()) {
			throw std::runtime_error("createKey");
		}

		/*****************************
			Export key to memory
		******************************/

		//calculate keyObject size for export
		if (!NT_SUCCESS(status = BCryptExportKey(
			hKey,
			NULL,
			BCRYPT_KEY_DATA_BLOB,
			NULL,
			0,
			&cbBlob,
			0)))
		{
			throw std::runtime_error("BCryptExportKey: " + sfy(status));
		}

		// Allocate blob
		pbBlob.clear();
		pbBlob.assign(cbBlob, 0);

		//export key to blob
		if (!NT_SUCCESS(status = BCryptExportKey(
			hKey,
			NULL,
			BCRYPT_KEY_DATA_BLOB,
			(PUCHAR)&pbBlob[0],
			cbBlob,
			&bytesWritten,
			0)))
		{
			throw std::runtime_error("BCryptExportKey: " + sfy(status));
		}
	}
	catch (const std::exception& e) {
		brb::err("KeyToMemory", e.what());
		delKey();
		return false;
	}
	delKey();
	return true;
}