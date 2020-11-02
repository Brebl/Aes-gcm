/****************************************************
	Test program to encrypt and decrypt stream of data
	AES-GCM
****************************************************/

void testf1();
void testf2();

int main()
{
	SetConsoleCP(1252);
	SetConsoleOutputCP(1252);
	std::wcout.imbue(std::locale(""));

	testf1();
	
}