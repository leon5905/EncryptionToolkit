#include "stdafx.h"
#include "CppUnitTest.h"
#include "KeyGenerator.h"
#include "EncryptionToolkit.h"
#include "SHA_512.h"
#include <iostream>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace EncryptionTest
{
	TEST_CLASS(SHA_512_Test)
	{
	public:

		//Testing using Official Test Vector
		//http://www.di-mgt.com.au/sha_testvectors.html
		//This page summarises useful test vectors for the secure hash algorithms SHA-1, SHA-2 and the new SHA-3 (approved as a FIPS standard in August 2015 [6]).

		TEST_METHOD(SHA_512_Official_TestVector) //Checking official test vectors
		{
			SHA_512 sha_512;
			std::string million_a = "";

			for (int i = 0; i < 1000000; i++) {
				million_a += 0x61;
			}

			std::string digest1 = sha_512.get_digest("");
			std::string digest2 = sha_512.get_digest("abc");
			std::string digest3 = sha_512.get_digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
			std::string digest4 = sha_512.get_digest("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
			std::string digest5 = sha_512.get_digest(million_a);

			std::string digest1_answer = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
			std::string digest2_answer = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
			std::string digest3_answer = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445";
			std::string digest4_answer = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";
			std::string digest5_answer = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";
			
			Assert::IsTrue(string_to_hex(digest1) == digest1_answer);
			Assert::IsTrue(string_to_hex(digest2) == digest2_answer);
			Assert::IsTrue(string_to_hex(digest3) == digest3_answer);
		    Assert::IsTrue(string_to_hex(digest4) == digest4_answer);
			Assert::IsTrue(string_to_hex(digest5) == digest5_answer);
		}

	private :
		std::string string_to_hex(const std::string& input) //Allow easier comparision by converting it to hex string.
		{
			static const char* const lut = "0123456789abcdef";
			size_t len = input.length();

			std::string output;
			output.reserve(2 * len);
			for (size_t i = 0; i < len; ++i)
			{
				const unsigned char c = input[i];
				output.push_back(lut[c >> 4]);
				output.push_back(lut[c & 15]);
				/*	output.push_back(' ');*/
			}
			return output;
		}
	};
}