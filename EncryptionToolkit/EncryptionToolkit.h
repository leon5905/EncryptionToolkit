#pragma once
#include <string>
#include "KeyGenerator.h"
#include "SHA_512.h"

namespace Encryption {
	class EncryptionToolkit {
	private:
		//Key Generator
		KeyGenerator key_gen;
		SHA_512 sha_512;

	public:
		EncryptionToolkit();

		//Stream
		std::string stream_encrypt();
		std::string stream_decrypt();

		//Hash
		std::string hash_sha512_compute(std::string message); //compute digest

		//MAC
		std::string hmac_compute(std::string key, std::string message); //Compute digest
		bool hmac_compare(std::string key, std::string message, std::string mac); //Compare received digest and computed digest

		//File Operation
		bool save_file(std::string file_path, std::string binary_str); //Save to File
		bool load_file(std::string file_path, std::string& binary_str); //Load from File

	};
}
