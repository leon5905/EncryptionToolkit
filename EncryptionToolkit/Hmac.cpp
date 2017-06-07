#include "Hmac.h"
#include"SHA_512.h"

Hmac::Hmac():block_size(128), hash(SHA_512())
{
}

std::string Hmac::hmac(std::string message, std::string key)
{
	unsigned int keyLength = key.length();

	if (keyLength > block_size) {
		key = this->hash.get_digest(key); //keys longer than blocksize are shorttened
	}

	keyLength = key.length();

	if (keyLength < block_size) {
		//keys shorter than blocksize are zero-padded(where || is concatenation
		int zero_byte_num = block_size - keyLength;

		for (int i = 0; i < zero_byte_num; i++) {
			key += (char) 0x00;
		}
	}

	//where blocksize is that of the underlying hash function
	std::string o_key_pad = "";
	std::string i_key_pad = "";

	for (int i = 0; i < block_size; i++) {
		o_key_pad += (0x5c ^ key.at(i));
		i_key_pad += (0x36 ^ key.at(i));
	}

	return this->hash.get_digest(o_key_pad + this->hash.get_digest(i_key_pad + message));
}

bool Hmac::hmac_verify(std::string message, std::string key, std::string mac) 
{
	if (Hmac::hmac(message, key) == mac)
		return true;

	return false;
}

