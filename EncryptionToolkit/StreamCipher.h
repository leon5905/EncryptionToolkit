#pragma once
#include <iostream>     
#include <memory>    
using namespace std;

namespace Encryption {
	class CRC4
	{
	public:
		CRC4();
		virtual ~CRC4();

		char* Encrypt(char *pszText, const char *pszKey); /* String value is converted into char array */
		char* Decrypt(char *pszText, const char *pszKey);

	private:
		unsigned char sbox[256];      /* Encryption array */
		unsigned char key[256], k;     /* Numeric key values */
		int  m, n, i, j, ilen;        /* Ambiguously named counters */
	};
}
