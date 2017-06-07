#include "stdafx.h"
#include "CppUnitTest.h"
#include "KeyGenerator.h"
#include "EncryptionToolkit.h"
#include "StreamCipher.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace StreamCipherTest
{
	TEST_CLASS(StreamCipherTest)
	{
	public:

		TEST_METHOD(StreamCipher_Encrypt_Decrypt) //Checking stream cipher can encrypt and decrpt back same data
		{
			char str[256], PT[256], DC[256];
			for (int i = 255; i >= 0; i--) {
				str[i] = i;
			}

			Encryption::CRC4 rc4;
			strcpy(PT, str);

			//Check for smaller key
			rc4.Encrypt(str, "123");
			rc4.Decrypt(str, "123");
			strcpy(DC, str);
			Assert::IsTrue(strcmp(PT, DC) == 0);

			//Check for larger key at 2048bit
			std::string key_256_byte;
			for (int i = 0; i < 256; i++) {
				key_256_byte += (char)0x3c;
			}

			rc4.Encrypt(str, key_256_byte.c_str());
			rc4.Decrypt(str, key_256_byte.c_str());
			strcpy(DC, str);
			Assert::IsTrue(strcmp(PT, DC) == 0);
		}

	};
}