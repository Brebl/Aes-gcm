#include "crypt.h"

void testf1()
{
	std::cout << "Object A:\n";
	Crypt a;	//encrypt
	std::cout << "Object B:\n";
	Crypt b;	//decrypt
	char teksti[] = "abcdefghijklmnopqrstuvwxyzåäö";
	DWORD ts = sizeof(teksti);

	//encrypt & save to file
	if (a.encrypt((BYTE*)teksti, ts)) {
		std::cout << "encryption success!\n";
	}
	else {
		std::cout << "encryption failed\n";
		return;
	}
	if (a.toFile(L"top.secret", (char*)teksti, ts)) {
		std::cout << "Saved to file\n";
		a.printBytes((PBYTE)teksti, ts);
	}

	//recover from file & decrypt
	if (b.fromFile(L"top.secret", (char*)teksti, ts)) {
		std::cout << "recoverd from file\n";
	}
	else {
		return;
	}
	if (b.decrypt((BYTE*)teksti, ts)) {
		std::cout << "decryption success!\n";
		b.printBytes((BYTE*)teksti, ts);
		std::cout << teksti << std::endl;
	}
	else {
		std::cout << "decryption failed\n";
		return;
	}
}