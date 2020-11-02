#include "crypt.h"

//stringify
std::string Crypt::sfy(const NTSTATUS& nts)
{
	std::stringstream ss;
	ss << "NTSTATUS=" << std::hex << nts;
	return ss.str();
}