#include "crypt.h"

bool Crypt::fromFile(const std::wstring& filename, char* data, const DWORD datasize)
{
	int flags = std::ios_base::binary;

	std::ifstream luku(filename, flags);
	if (luku.is_open()) {
		luku.read(reinterpret_cast<char*>(&nonce[0]), sizeof(nonce));
		luku.read(reinterpret_cast<char*>(&authTag[0]), sizeof(authTag));
		luku.read(data, datasize);
		luku.close();
		return true;
	}
	else
		return false;
}