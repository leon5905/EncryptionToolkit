#include "stdafx.h"
#include "CppUnitTest.h"
#include "../EncryptionToolkit/KeyGenerator.h"
#include "../EncryptionToolkit/EncryptionToolkit.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace EncryptionTest
{		
	//IInclude .h and .cpp as existing file
	TEST_CLASS(KeyGeneratorTest)
	{
	public:
		Encryption::KeyGenerator key_gen;
		
		TEST_METHOD(GenerateKey_CheckKeyLength) //Testing to check a range of key length matches the output of the function
		{
			//Init
			int arr_size = 8;
			size_t byte_size[] {1,2,3,4,5,32,33,64}; //Test cases for key length <32 and >=32
			std::string key[8];
			for (int i = 0; i < arr_size; i++) {
				key[i] = key_gen.generate_key(byte_size[i]);
			}

			//Testing for generate number length == requested byte size
			for (int i = 0; i < arr_size; i++) {
				Assert::IsTrue( (key[i].length() ) == byte_size[i]);
			}

		}

		//New seed just set the random nubmer generator to a new seed
		TEST_METHOD(GenerateKey_CheckNewSeed) //Testing to check a range of key length matches the output of the function
		{
			//Init
			int arr_size = 8;
			size_t byte_size[]{ 1,2,3,4,5,32,33,64 };
			std::string key[8];
			for (int i = 0; i < arr_size; i++) {
				key[i] = key_gen.generate_key_new_seed(byte_size[i]);
			}

			//Testing
			for (int i = 0; i < arr_size; i++) {
				Assert::IsTrue((key[i].length()) == byte_size[i]);
			}
		}

	};
}