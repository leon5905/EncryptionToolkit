#include <algorithm>
#include <stdexcept>
#include <iostream>
#include "EncryptionToolkit.h"
#include "KeyGenerator.h"
#include "StreamCipher.h"
#include "Hmac.h"

using namespace std;
using namespace Encryption;

string string_to_hex(const string&);
//string hex_to_string(const string& input);

int main() {
	cout << "Encryption Toolkit Demo \n\n";

	KeyGenerator keygen;
	cout << keygen.generate_key(5) << "\n\n";

	string s = "";
	char aChar[256];
	for (int i = 0; i < 256; i++) {
		aChar[i] = i;

		char a = i;
		s += a;
	}
	aChar[0] = 1;
	aChar[255] = 0;

	cout << string_to_hex(s) << "\n\n";

	Encryption::EncryptionToolkit toolkit;
	toolkit.save_file("main.bin", s);

	string file;
	toolkit.load_file("main.bin", file);
	cout << string_to_hex(file);

	cout << "\n\n";

	std::string key_1 = "";
	std::string key_2 = "Jefe";
	std::string key_3 = "";

	std::string data_1 = "Hi There";
	std::string data_2 = "what do ya want for nothing?";
	std::string data_3 = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

	for (int i = 0; i < 20; i++) {
		key_1 += 0x0b;
	}

	for (int i = 0; i < 131; i++) {
		key_3 += 0xaa;
	}

	Hmac hmac;
	//std::string hmac1 = hmac.hmac(key_1, data_1);
	//std::string hmac2 = hmac.hmac(key_2, data_2);
	std::string hmac3 = hmac.hmac(key_3, data_3);

	std::string hmac1_answer = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";
	std::string hmac2_answer = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
	std::string hmac3_answer = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58";

	cout << string_to_hex(hmac3) <<endl<<endl;

	getchar();
	
}

std::string string_to_hex(const std::string& input)
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
		output.push_back(' ');
	}
	return output;
}
void streamcipher_display() {
	char str[256];
	for (int i = 255; i >= 0; i--) {
		str[i] = i;
	}

	CRC4 rc4;
	cout << "Plain text: " << str << "\n";
	rc4.Encrypt(str, "Key");
	cout << "Encode: " << str << "\n";
	rc4.Decrypt(str, "Key");
	cout << "Decode: " << str << "\n";
}

//std::string hex_to_string(const std::string& input)
//{
//	static const char* const lut = "0123456789ABCDEF";
//	size_t len = input.length();
//	if (len & 1) throw std::invalid_argument("odd length");
//
//	std::string output;
//	output.reserve(len / 2);
//	for (size_t i = 0; i < len; i += 2)
//	{
//		char a = input[i];
//		const char* p = std::lower_bound(lut, lut + 16, a);
//		if (*p != a) throw std::invalid_argument("not a hex digit");
//
//		char b = input[i + 1];
//		const char* q = std::lower_bound(lut, lut + 16, b);
//		if (*q != b) throw std::invalid_argument("not a hex digit");
//
//		output.push_back(((p - lut) << 4) | (q - lut));
//	}
//	return output;
//}