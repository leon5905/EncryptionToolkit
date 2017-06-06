#pragma once
#include <iostream>     
#include <memory>    
using namespace std;
#define SWAP(a, b) ((a) ^= (b), (b) ^= (a), (a) ^= (b))
namespace Encryption {
	class CRC4
	{
	public:
		CRC4()
		{
			memset(sbox, 0, 256);
			memset(key, 0, 256);
		}
		virtual ~CRC4()
		{
			memset(sbox, 0, 256);  /* remove Key traces in memory  */
			memset(key, 0, 256);
		}
		char* Encrypt(char *pszText, const char *pszKey); /* String value is converted into char array */
		char* Decrypt(char *pszText, const char *pszKey);

	private:
		unsigned char sbox[256];      /* Encryption array */
		unsigned char key[256], k;     /* Numeric key values */
		int  m, n, i, j, ilen;        /* Ambiguously named counters */
	};
}

