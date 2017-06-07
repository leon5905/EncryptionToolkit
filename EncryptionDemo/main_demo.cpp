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
void demo_save_load();
void demo_key_gen();
void demo_stream_cipher();
void demo_hash_512();
void demo_hmac();
//string hex_to_string(const string& input);

int main() {
	//KeyGenerator keygen;
	//cout << keygen.generate_key(5) << "\n\n";
	demo_save_load();
	demo_key_gen();
	demo_stream_cipher();
	demo_hash_512();
	demo_hmac();
}

void demo_save_load() {
	cout << "Encryption Toolkit Demo \n";
	cout << "1) Demo Save file, Load File \n\n";

	string s = "";
	char aChar[256];
	for (int i = 0; i < 256; i++) {
		aChar[i] = i;

		char a = i;
		s += a;
	}
	aChar[0] = 1;
	aChar[255] = 0;

	cout << "Hex Value Data to save\n\n";
	cout << string_to_hex(s) << "\n\n";

	cout << "Saving File...\n\n";
	Encryption::EncryptionToolkit toolkit;
	toolkit.save_file("TestingSaveFileFunction.bin", s);

	cout << "Loading File...\n\n";
	string file;
	toolkit.load_file("TestingSaveFileFunction.bin", file);
	cout << "Loaded Hexa Decimal Value...\n\n";
	cout << string_to_hex(file);

	cout << "\n\nSave File and Load File Demo Success!!!\n\n";
	cout << "\n\n";

	system("pause");
	system("cls");
}

void demo_key_gen() {
	cout << "Encryption Toolkit Demo \n";
	cout << "2) Demo Key Generator \n\n";

	Encryption::EncryptionToolkit toolkit;

	cout << "Displaying Hexadeicmal Value of Key\n\n";

	cout << "Genearting 1 byte key size\n\n";
	cout << string_to_hex(toolkit.generate_key(1)) << "\n\n";

	cout << "Genearting 2 byte key size\n\n";
	cout << string_to_hex(toolkit.generate_key(2)) << "\n\n";

	cout << "Genearting 32 byte key size\n\n";
	cout << string_to_hex(toolkit.generate_key(32)) << "\n\n";

	cout << "Genearting 64 byte key size\n\n";
	cout << string_to_hex(toolkit.generate_key(64)) << "\n\n";

	cout << "\n\nKey Generator Demo End...\n\n";
	cout << "\n\n";

	system("pause");
	system("cls");
}

void demo_stream_cipher() {
	cout << "Encryption Toolkit Demo \n";
	cout << "3) Stream Cipher \n\n";

	Encryption::EncryptionToolkit toolkit;
	std::string plain_text = "Hello World!";
	std::string key = "secretsharedkey";
	cout << "Plain text: " << plain_text << "\n\n";

	std::string cipher_text = toolkit.stream_encrypt(plain_text, key);
	cout << "Encrpyting Data....\n";
	cout << "Cipher text: " << cipher_text << "\n\n";

	cout << "Decrpyting Data....\n";
	cout << "Decrpypted text: " << toolkit.stream_decrypt(cipher_text,key) << "\n\n";
	cout << "Original Plain text: " << plain_text << "\n";

	cout << "\n\nStream Cipher Demo End...\n\n";

	system("pause");
	system("cls");
}

void demo_hash_512() {
	cout << "Encryption Toolkit Demo \n";
	cout << "4) Hash (SHA_512) Demo \n\n";

	Encryption::EncryptionToolkit toolkit;
	std::string plain_text = "abc";
	cout << "Plain text: " << plain_text << "\n\n";

	std::string digest = toolkit.hash_sha512_compute(plain_text);
	cout << "Digesting Data....\n";
	cout << "Digested text (Hexadecimal Value): " << string_to_hex(digest) << "\n\n";

	cout << "Expected Digest for SHA-512 (Hexa): " << "dd af 35 a1 93 61 7a ba cc 41 73 49 ae 20 41 31 12 e6 fa 4e 89 a9 7e a2 0a 9e ee e6 4b 55 d3 9a 21 92 99 2a 27 4f c1 a8 36 ba 3c 23 a3 fe eb bd 45 4d 44 23 64 3c e8 0e 2a 9a c9 4f a5 4c a4 9f" << "\n";

	cout << "\n\nShowing how one slight change in value will result in different hash\n\n";
	plain_text = "abd";
	cout << "Modified text: " << plain_text << "\n\n";
	cout << "Modified text's Digest (Hexadecimal Value): " << string_to_hex(toolkit.hash_sha512_compute(plain_text)) << "\n\n";

	cout << "\n\nHash Demo End...\n\n";

	system("pause");
	system("cls");
}

void demo_hmac() {
	cout << "Encryption Toolkit Demo \n";
	cout << "5) HMAC Demo \n\n";

	Encryption::EncryptionToolkit toolkit;
	std::string original_text = "abc";
	std::string key = "random key";
	cout << "Original text: " << original_text << "\n\n";

	std::string mac = toolkit.hmac_compute(original_text,key);
	cout << "Computing MAC....\n";
	cout << "\n\nMac in Hexa = \n" << string_to_hex(mac) <<"\n\n";
	
	cout << "Sending Message and Mac to another person\n";
	cout << "Another person compute message using secret key and compare to recieved mac to idetify whether message have been modified or not\n\n";

	cout << "Received text: " << original_text << "\n\n";
	cout << "Computing New Mac....\n";
	cout << "\n\nMac in Hexa = \n" << string_to_hex(toolkit.hmac_compute(original_text, key)) << "\n\n";

	cout << (((toolkit.hmac_compare(original_text, key, mac))==true)?"Message have not been modified":"Message Have been modified");

	cout << "\n---------------------------------------------\n";
	cout << "\n\nWhat if received text have been modified?\n";
	std::string received_text = "abd";
	cout << "Received Modified text: " << received_text << "\n\n";
	std::string new_mac = toolkit.hmac_compute(received_text, key);
	cout << "Computing New MAC....\n";
	cout << "\n\nMac in Hexa = \n" << string_to_hex(new_mac) << "\n\n";

	if (new_mac != mac) {
		cout << "ALERT!! Message HAVE been modified!!\n";
	}
	else {
		cout << "Message have not been modified\n";
	}


	cout << "\n\n\n\nMac Demo End...\n\n";

	cout << "\n\nEncrpytion Toolkit Demo End Here...\n\n";

	system("pause");
	system("cls");
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

//std::string SHA_512::convertToBitString(unsigned long long value)
//{
//	std::string str(64, '0');
//
//	for (int i = 0; i < 64; i++)
//	{
//		if ((1ll << i) & value)
//			str[63 - i] = '1';
//	}
//
//	str.insert(8, 1, ' ');
//	str.insert(17, 1, ' ');
//	str.insert(26, 1, ' ');
//	str.insert(35, 1, ' ');
//
//
//	return str;
//}