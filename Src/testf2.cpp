#include "crypt.h"

void testf2() {

	std::cout << "Object A:\n";
	Crypt a;	//encrypt
	std::cout << "Object B:\n";
	Crypt b;	//en/decrypt obj c
	std::cout << "Object C:\n";
	Crypt c;	//decrypt
	char teksti[] = "abcdefghijklmnopqrstuvwxyzåäö";
	DWORD ts = sizeof(teksti);

	//encrypt & save to file
	if (a.encrypt((BYTE*)teksti, ts)) {
		std::cout << "encryption success!\n";
	}
	else {
		std::cout << "encryption failed\n";
	}
	a.toFile(L"top.secret", (char*)teksti, ts);
	a.printBytes((PBYTE)teksti, ts);

	//encrypt object
	if (b.encrypt((PBYTE)&c, sizeof(c))) {
		std::cout << "object encryption success!\n";
	}
	else {
		std::cout << "object encryption failed\n";
	}

	//decypt object
	if (b.decrypt((BYTE*)&c, sizeof(c))) {
		std::cout << "object decryption success!\n";
	}
	else {
		std::cout << "object decryption failed\n";
	}

	//recover from file
	c.fromFile(L"top.secret", (char*)teksti, ts);
	if (c.decrypt((BYTE*)teksti, ts)) {
		std::cout << "decryption success!\n";
		c.printBytes((BYTE*)teksti, ts);
		std::cout << teksti << std::endl;
	}
	else {
		std::cout << "decrypt failed\n";
	}
}