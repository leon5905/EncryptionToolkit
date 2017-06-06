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

		TEST_METHOD(StreamCipher) //Checking whether save file can save data and load file can load back the same data.
		{
			char str[256], PT[256], DC[256];
			for (int i = 255; i >= 0; i--) {
				str[i] = i;
			}

			Encryption::CRC4 rc4;
			strcpy(PT, str);

			rc4.Encrypt(str, "Key");

			rc4.Decrypt(str, "Key");
			strcpy(DC, str);
			Assert::IsTrue(strcmp(PT, DC) == 0);
		}

	};
}