#include "crypt.h"

Crypt::validity Crypt::validatePwd(const std::wstring& pwd, const DWORD pwdMinSize, const DWORD pwdMaxSize, const unsigned minVal)
{
	unsigned val = 0;	//pwd validity
	if (pwd.size() < pwdMinSize) {
		return validity::_tooShort;
	}
	if (pwd.size() > pwdMaxSize) {
		return validity::_tooLong;
	}
	if (pwd.find_first_of(L"abcdefghijklmnopqrstuvwxyzåäö") != std::string::npos) {
		val++;
	}
	if (pwd.find_first_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ") != std::string::npos) {
		val++;
	}
	if (pwd.find_first_of(L"1234567890") != std::string::npos) {
		val++;
	}
	if (pwd.find_first_of(L"!\"#¤%&/()=?@£${[]}") != std::string::npos) {
		val++;
	}
	if (val < minVal) {
		return validity::_tooWeak;
	}
	else
		return validity::_valid;
}