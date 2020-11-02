#include "crypt.h"

void Crypt::printBytes (BYTE const* data, DWORD dataSize)
{
		std::cout.setf(std::ios::hex, std::ios::basefield);
		std::cout.fill('0');
		for (DWORD i = 0; i < dataSize; i++, data++) {
			if (i % sizeof(ULONGLONG) == 0) {
				std::cout << std::endl;
			}
			std::cout.width(2);
			std::cout << static_cast<unsigned>(*data) << " ";
		}
		std::cout << std::endl;
}