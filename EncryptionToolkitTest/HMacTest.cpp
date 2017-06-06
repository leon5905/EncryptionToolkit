#include "stdafx.h"
#include "CppUnitTest.h"
#include "KeyGenerator.h"
#include "EncryptionToolkit.h"
#include "Hmac.h"
#include <iostream>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace EncryptionTest
{
	TEST_CLASS(HMAC_Test_)
	{
	public:

		//Testing using recommended Test Vector
		//https://tools.ietf.org/pdf/rfc4231.pdf

		TEST_METHOD(HMAC_Test_TestVector) //Checking official test vectors
		{
			Hmac hmac;
			std::string key_1 = "";
			std::string key_2 = "Jefe";
			std::string key_3 = "";

			std::string data_1 = "Hi There";
			//Test with a key shorter than the length of the HMAC output.
			std::string data_2 = "what do ya want for nothing?";
			//Test with a key and data that is larger than 128 bytes (= block-size of SHA - 512)
			std::string data_3 = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

			for (int i = 0; i < 20; i++) {
				key_1 += 0x0b;
			}

			for (int i = 0; i < 131; i++) {
				key_3 += 0xaa;
			}

			std::string hmac1 = hmac.hmac(key_1, data_1);
			std::string hmac2 = hmac.hmac(key_2, data_2);
			std::string hmac3 = hmac.hmac(key_3, data_3);

			std::string hmac1_answer = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";
			std::string hmac2_answer = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
			std::string hmac3_answer = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58";

			Assert::IsTrue(string_to_hex(hmac1) == hmac1_answer);
			Assert::IsTrue(string_to_hex(hmac2) == hmac2_answer);
			Assert::IsTrue(string_to_hex(hmac3) == hmac3_answer);
		}

	private:
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