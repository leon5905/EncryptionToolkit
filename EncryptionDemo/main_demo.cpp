#include <algorithm>
#include <stdexcept>
#include <iostream>
#include "EncryptionToolkit.h"
#include "KeyGenerator.h"
#include "StreamCipher.h"

using namespace std;
using namespace Encryption;

string string_to_hex(const string&);
//string hex_to_string(const string& input);
//Demo pull request

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

	getchar();
	
}

std::string string_to_hex(const std::string& input)
{
	static const char* const lut = "0123456789ABCDEF";
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