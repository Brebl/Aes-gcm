#include "crypt.h"

void Crypt::askPwd(wchar_t* pwd, DWORD& pwd_size, const DWORD pwd_maxSize,const validity val)
{
	switch (val) {
	case validity::_null:
		//please enter a password
		std::cout << "Please enter a password.\n";
		break;
	case validity::_tooShort:
		//your password is too short, please enter a new one
		std::cout << "Your password is too short, please enter a new one.\n";
		break;
	case validity::_tooWeak:
		//your password is too weak, please enter a better one
		std::cout << "your password is too weak, please enter a better one.\n";
		break;
	case validity::_valid:
		//you have allready entered a valid password
		brb::log("askPwd", "allready entered validity::_valid");
		return;
	default:
		assert(false);
	}
	//reset pwd
	for (DWORD i = 0; i < pwd_maxSize; i++) {
		pwd[i] = L'\0';
	}
	//write pwd
	std::wcin.getline(pwd, pwd_maxSize);
	//calc siz
	for (DWORD i = 0; i < pwd_maxSize; i++) {
		if (pwd[i] == L'\0') {
			pwd_size = i;
			brb::log("pwd size", i, brb::mode::debug_only);
			return;
		}
	}
	//TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_TooLongTestPassword_
	brb::log("pwd size", "too long");
	return;
}