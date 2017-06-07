#include "stdafx.h"
#include "CppUnitTest.h"
#include "KeyGenerator.h"
#include "EncryptionToolkit.h"
#include "SHA_512.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace EncryptionTest
{
	TEST_CLASS(EncryptionToolkitTest)
	{
	public:

		TEST_METHOD(SaveFile_LoadFile_CheckFunctionality) //Checking whether save file can save data and load file can load back the same data.
		{
			std::string s = "";
			for (int i = 0; i < 256; i++) { //Test for all 0-255 Char Value
				char a = i;
				s += a;
			}

			Encryption::EncryptionToolkit toolkit;
			toolkit.save_file("unit_testing.bin", s);

			std::string file;
			toolkit.load_file("unit_testing.bin", file);

			Assert::IsTrue( file.compare(s)==0 );
		}

		//Check all other function here
		TEST_METHOD(EncryptionToolKit_Test_Wrapper)
		{
			//Test whether function wrapping 
			Encryption::EncryptionToolkit toolkit;

			std::string message = "text Message";
			//Key Gen Test
			std::string key = toolkit.generate_key(128); //1024 bit key / 128 byte

			//Stream cipher test
			std::string stream_cipher_test= toolkit.stream_decrypt(toolkit.stream_encrypt(message,key),key);
			Assert::IsTrue(stream_cipher_test == message);

			//Hash Test
			SHA_512 sha;
			Assert::IsTrue(toolkit.hash_sha512_compute(message)== sha.get_digest(message));

			//Hmac Test
			Assert::IsTrue(toolkit.hmac_compare(message,key, toolkit.hmac_compute(message, key)));
			Assert::IsFalse(toolkit.hmac_compare("modified message", key, toolkit.hmac_compute(message, key)));
		}
	};
}