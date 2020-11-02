#include "crypt.h"

bool Crypt::toFile(const std::wstring& filename, char* data, const DWORD datasize)
{
	int flags = std::ios_base::binary;

	std::ofstream output(filename, flags);
	if (output.is_open()) {
		output.write(reinterpret_cast<char*>(&nonce[0]), sizeof(nonce));
		output.write(reinterpret_cast<char*>(&authTag[0]), sizeof(authTag));
		output.write(data, datasize);
		output.close();
		return true;
	}
	else
		return false;
}