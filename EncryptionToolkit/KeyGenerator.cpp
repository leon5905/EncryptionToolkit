#include "KeyGenerator.h"
#include <random>
#include <chrono>
#include <math.h>

Encryption::KeyGenerator::KeyGenerator()
{
	random_engine = std::mt19937(time(0)); //using mersenne twister RNG
}

std::string Encryption::KeyGenerator::generate_key(int byte_size)
{
	std::string key="";
	
	int loopCount = static_cast<int>(std::floor( byte_size*8.0 / 32)); //Loop Count - Each loop generate 4 byte (remainder is generated outside the loop)
	int remainderCount = (byte_size*8)%32;
	remainderCount /= 8; // How many byte left to to fill in (outside the main loop)

	for (int i = 0; i <loopCount; i++) {
		uint32_t random_32_bit = random_engine();

		char bytes[4];

		bytes[0] = (random_32_bit >> 24) & 0xFF;
		bytes[1] = (random_32_bit >> 16) & 0xFF;
		bytes[2] = (random_32_bit >> 8) & 0xFF;
		bytes[3] = random_32_bit & 0xFF;

		key += bytes[0];
		key += bytes[1];
		key += bytes[2];
		key += bytes[3];
	}

	if (remainderCount > 0) {
		uint32_t random_32_bit = random_engine();

		char bytes;

		for (int i = 0; i < remainderCount; i++) {
			bytes = ( random_32_bit >> ( 24-(i*8) ) ) & 0xFF;
			key += bytes;
		}
	}

	return key;
}

//More secure but slower
std::string Encryption::KeyGenerator::generate_key_new_seed(int byte_size)
{
	std::random_device rd; //reseed the generator
	random_engine = std::mt19937(rd);
	return generate_key(byte_size);
}
