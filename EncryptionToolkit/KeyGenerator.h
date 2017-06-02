#pragma once
#include <random>
#include <string>

namespace Encryption {
	class KeyGenerator {
	private:
		std::mt19937 random_engine;

	public:
		KeyGenerator();
		std::string generate_key(int byte_size); //string value is in binary char (means may contain '\0' / 0 value in the string)
		std::string generate_key_new_seed(int byte_size);
	};
}