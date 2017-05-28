#pragma once
#include <string>
#include "KeyGenerator.h"

//FAQ
//The following header is only a template/suggestion, u can change your function signature if deem necessary.
//If you think u need a class, go ahead and add in another cpp and .h file.

//Create a branch to work on your version, and then commit the changes.
//WZ will pull all commit request and merge them. 
//For more guide on how to use github, visit https://guides.github.com/activities/hello-world/

//Try to find working implemetation and copy them.
//Key Gen - WZ
//Stream - Kee
//Hash - Cy (SHA 512)
//MAC  - Keat (hmac using sha512 or others)

//Requirement stated by Assignment Question PDF 
//Secure text files or image files using the assigned keys.
//The cryptographic toolkit must be able to generate ciphertexts, hash values or MAC values as standalone files 

//SPECIAL TECHNICAL NOTE
//C++17 only got std::byte
//Therefore it is opted to use unsinged int 8 bit as byte
//_declspec(dllexport) export the public class function as lib

namespace Encryption {
	class EncryptionToolkit {
	private:
		//Key Generator
		KeyGenerator key_gen;

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
