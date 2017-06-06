#include "Hmac.h"

Hmac::Hmac():block_size(512)
{
}

std::string Hmac::hmac(std::string key, std::string message)
{
	if (key.length() > block_size) {
		key = hash(key); //keys longer than blocksize are shorttened
	}
	if (key.length() < block_size) {
		//keys shorter than blocksize are zero-padded(where || is concatenation
		int zero_bit_num = block_size - key.length();

		int zero_byte_num = zero_bit_num / 8;

		for (int i = 0; i < zero_byte_num; i++) {
			key = key + (char) 0x00;
		}

	}
	//where blocksize is that of the underlying hash function
	std::string o_key_pad = (0x5c * block_size) ^ key.length;
	std::string i_key_pad = (0x36 * block_size) ^ key.length;


	return hash(o_key_pad + hash(i_key_pad + message));
}

bool Hmac::hmac_verify(std::string key, std::string message, std::string mac)
{
	if (Hmac::hmac(key, message) == mac)
		return true;

	return false;
}
