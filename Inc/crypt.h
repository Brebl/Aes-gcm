#pragma once
//crypt
#include <windows.h>
#include <bcrypt.h>

class Crypt
{
private:
	enum class validity {
		_null,
		_tooShort,
		_tooLong,
		_tooWeak,
		_valid
	};

	BCRYPT_ALG_HANDLE       hAlg = NULL;		//Algorithm handle
	BCRYPT_KEY_HANDLE       hKey = NULL;		//Key handle
	std::vector<BYTE>		keyObj;				//Key object
	DWORD					cbKey = 0;			//Key object size
	std::vector<BYTE>		pbBlob;	//ptr to secure memory-zone, key stored here
	DWORD					cbBlob = 0;			//secure memory-zone size
	NTSTATUS                status = 0;			//error code
	DWORD					bytesWritten = 0;	//as it stands

	static const DWORD		hashSize = 32;		//256bit
	static const DWORD		pwd_maxSize = 256;	//whatever
	static const DWORD		gcmNonceSize = 12;	//96bit
	std::array<BYTE, gcmNonceSize> nonce{ 0 };	//IV(nonce)
	std::vector<BYTE>		authTag;			//tag
	BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;	//tagin lisätiedot
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO acmi;	//cryptauksen lisätiedot


	bool createNonce();	//generate IV(nonce)
	bool createKey();	//create key for cryption
	volatile bool keyToM();		//store key to secure memory-zone
	volatile bool keyFromM();	//import key from secure memory-zone
	void delKey();		//delete key
	void askPwd(wchar_t* pwd, DWORD& pwd_size, const DWORD pwd_maxSize,const validity);	//user input password
	validity validatePwd(
		const std::wstring& pwd, 
		const DWORD pwdMinSize = 8, 
		const DWORD pwdMaxSize = 64, 
		const unsigned minVal = 3);
	std::string displayError(DWORD NTStatusMessage);	//NTStatus to stdout

public:
	Crypt();
	std::string sfy(const NTSTATUS& nts);
	void printBytes(BYTE const* data, DWORD dataSize);
	bool encrypt(PBYTE data, DWORD dataSize);	//encrypt inplace
	bool decrypt(PBYTE data, DWORD dataSize);	//decrypt inplace
	bool toFile(const std::wstring& filename, char* data, const DWORD datasize);		//store crypted data to file
	bool fromFile(const std::wstring& filename, char* data, const DWORD datasize);	//recover crypted data from file
};

