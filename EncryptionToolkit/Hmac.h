#pragma once
#include <string>
#include "SHA_512.h"

class Hmac {
private:
	unsigned int block_size;
	SHA_512 hash;

public:
	Hmac();
	std::string hmac(std::string message, std::string key);
	bool hmac_verify(std::string message, std::string key, std::string mac);
};
