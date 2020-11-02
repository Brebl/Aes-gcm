#include "crypt.h"

void Crypt::delKey()
{
	try {
		if (hKey) {
			if (!NT_SUCCESS(status = BCryptDestroyKey(hKey))) {
				throw std::runtime_error("BCryptDestroyKey: " + sfy(status));
			}
			hKey = 0;
		}
	}
	catch (const std::exception& e) {
		brb::err("delKey", e.what());
	}
}