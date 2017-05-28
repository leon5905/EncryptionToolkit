#include "EncryptionToolkit.h"
#include <fstream>
#include <string>

Encryption::EncryptionToolkit::EncryptionToolkit() : key_gen(KeyGenerator()){}

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
