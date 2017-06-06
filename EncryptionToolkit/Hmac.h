#pragma once
#include <string>

class Hmac {
private:
	int block_size;

public:
	Hmac();
	std::string hmac(std::string key, std::string message);
	bool hmac_verify(std::string key, std::string message, std::string mac);
};
