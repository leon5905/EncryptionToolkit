#pragma once
#include <string>
#include "KeyGenerator.h"
#include "SHA_512.h"
#include "Hmac.h"
#include "StreamCipher.h"

namespace Encryption {
	class EncryptionToolkit {
	private:
		KeyGenerator key_gen;
		SHA_512 sha_512;
		Hmac hmac;
		CRC4 stream_cipher;

	public:
		EncryptionToolkit();

		//Stream
		std::string stream_encrypt(std::string message, std::string key); //Encrypt
		std::string stream_decrypt(std::string cipher_text, std::string key); //Decrypt

		//Hash
		std::string hash_sha512_compute(std::string message); //compute digest

		//MAC
		std::string hmac_compute(std::string message, std::string key); //Compute digest
		bool hmac_compare(std::string message, std::string key, std::string mac); //Compare received digest and computed digest, false means message have been tampered.

		//Random Key
		std::string generate_key(int byte_size); //Generate key for specified byte size

		//File Operation
		bool save_file(std::string file_path, std::string binary_str); //Save to File
		bool load_file(std::string file_path, std::string& binary_str); //Load from File

	};
}
