#include "EncryptionToolkit.h"
#include <fstream>
#include <string>

Encryption::EncryptionToolkit::EncryptionToolkit() : key_gen(KeyGenerator()), sha_512(SHA_512()), hmac(Hmac()),stream_cipher(CRC4()){}

std::string Encryption::EncryptionToolkit::stream_encrypt(std::string message, std::string key)
{
	std::unique_ptr<char[]> writable(new char[message.size() + 1]);

	std::copy(message.begin(), message.end(), writable.get());
	writable.get()[message.size()] = '\0';

	return stream_cipher.Encrypt(writable.get(), key.c_str());
}

std::string Encryption::EncryptionToolkit::stream_decrypt(std::string cipher_text, std::string key)
{
	std::unique_ptr<char[]> writable(new char[cipher_text.size() + 1]);

	std::copy(cipher_text.begin(), cipher_text.end(), writable.get());
	writable.get()[cipher_text.size()] = '\0';

	return stream_cipher.Encrypt(writable.get(), key.c_str());
}

std::string Encryption::EncryptionToolkit::hash_sha512_compute(std::string message)
{
	return sha_512.get_digest(message);
}

std::string Encryption::EncryptionToolkit::hmac_compute(std::string message, std::string key)
{
	return hmac.hmac(message, key);
}

bool Encryption::EncryptionToolkit::hmac_compare(std::string message, std::string key, std::string mac)
{
	return hmac.hmac_verify(message,key,mac);
}

std::string Encryption::EncryptionToolkit::generate_key(int byte_size)
{
	return key_gen.generate_key(byte_size);
}

bool Encryption::EncryptionToolkit::save_file(std::string file_path, std::string binary_str)
{
	std::ofstream out_stream;

	try {
		out_stream.open(file_path, std::ofstream::out | std::ofstream::binary);
		out_stream << binary_str;
		out_stream.close();
	}
	catch (...){
		return false;
	}

	return true;
}

bool Encryption::EncryptionToolkit::load_file(std::string file_path, std::string& binary_str)
{
	std::ifstream in_stream;
	binary_str = "";

	try {
		in_stream.open(file_path, std::ifstream::binary | std::ifstream::in);

		char c;
		while (in_stream.get(c)) {
			binary_str += c;
		}

		in_stream.close();
	}
	catch (...) {
		return false;
	}

	return true;
}
