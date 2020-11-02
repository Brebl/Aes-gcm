#include "crypt.h"

bool Crypt::createNonce()
{
	try {
		if (!NT_SUCCESS(status = BCryptGenRandom(
			BCRYPT_RNG_ALG_HANDLE,
			&nonce[0],
			gcmNonceSize,
			0)))
		{
			throw std::runtime_error("BCryptGenRandom: " + sfy(status));
		}
	}
	catch (const std::exception& e) {
		brb::err("createNonce", e.what());
		return false;
	}
	return true;
}