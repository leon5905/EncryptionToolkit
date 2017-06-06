#include "SHA_512.h"
#include <assert.h>  
#include <iostream>
#include <iomanip>

#define SHA512_SHFR(x, n)    (x >> n)
#define SHA512_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n))) //sizeof(x) << 3 == sizeof(x) * 8
#define SHA512_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA512_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA512_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA512_SIGMA_BIG_0(x) (SHA512_ROTR(x, 28) ^ SHA512_ROTR(x, 34) ^ SHA512_ROTR(x, 39))
#define SHA512_SIGMA_BIG_1(x) (SHA512_ROTR(x, 14) ^ SHA512_ROTR(x, 18) ^ SHA512_ROTR(x, 41))
#define SHA512_SIGMA_SMALL_0(x) (SHA512_ROTR(x,  1) ^ SHA512_ROTR(x,  8) ^ SHA512_SHFR(x,  7))
#define SHA512_SIGMA_SMALL_1(x) (SHA512_ROTR(x, 19) ^ SHA512_ROTR(x, 61) ^ SHA512_SHFR(x,  6))

SHA_512::SHA_512()
{
}

//Implementation is done following the guideline outlined in official guide
//http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf

std::string SHA_512::get_digest(std::string message)
{
	h[0] = 0x6a09e667f3bcc908;
	h[1] = 0xbb67ae8584caa73b;
	h[2] = 0x3c6ef372fe94f82b;
	h[3] = 0xa54ff53a5f1d36f1;
	h[4] = 0x510e527fade682d1;
	h[5] = 0x9b05688c2b3e6c1f;
	h[6] = 0x1f83d9abfb41bd6b;
	h[7] = 0x5be0cd19137e2179;

	//Pre-processing
	unsigned long long messageBitNum =  static_cast<unsigned long long>( message.length() ) * 8; //Example "abc" ~ 8bit x3 = 24 = 11000b

	unsigned int length_plus_1_mod_1024 = (messageBitNum + 1)%1024 ;

	unsigned int zeroBit = 0;
	
	//Calculate how many zero to pad 
	if (length_plus_1_mod_1024<=896)
		zeroBit = (896 - length_plus_1_mod_1024); 
	else {
		unsigned int difference = length_plus_1_mod_1024 - 896;
		zeroBit = 1024 - difference;
	}

	unsigned int zerobitByteBlock = (zeroBit+1) / 8; //Calculate whole zero bit byte block

	//std::cout << "\nMessageLength (in bit) = " << messageBitNum;
	//std::cout << "\n1+Zero bit to pad = " << zeroBit+1;
	//std::cout << "\n1+Zero bit byte block = " << zerobitByteBlock << "\n";

	assert(zerobitByteBlock != 0); //Cannot be zero

	unsigned char block;
	block = 0x80; //1000 0000
	message += block; 

	zerobitByteBlock--;
	block = 0x00;
	for (unsigned int i = 0; i < zerobitByteBlock; i++) {
		message += block;
	}

	//Append 128-bit Big-endian message length
	message += block;
	message += block;
	message += block;
	message += block;
	message += block;
	message += block;
	message += block;
	message += block;
	for (int i = 7; i >= 0; i--) {
		block = messageBitNum >> (i*8);
		//std::cout << "block = " << (unsigned int)block << "\n";
		message += block;
	}

	assert( (static_cast<unsigned long long>(message.length() ) * 8 ) % 1024 == 0 ); //Multiple of 1024 must be

	//Parsing the message into N 1024 bit chunks
	//Each chunk is 128 byte or 128 message length
	unsigned long long n1024_block_num = static_cast<unsigned long long>(message.length() ) / 128; //128 *8 = 1024
	//std::cout << "\nBlock Number = " << n1024_block_num;
	//std::cout << "\nMessage Length = " << message.length();

	std::string* M = new std::string[n1024_block_num];
	for (unsigned long long i = 0; i < n1024_block_num; i++) {
		M[i] = message.substr(i*128,128);
	}

	//std::cout << "\nMessage = " << message;
	//std::cout << "\nMessage M = " << M[0];

	unsigned long long w[80];
	for (int i = 0; i < 80; i++) {
		w[i] = 0;
	}

	for (unsigned long long i = 0; i < n1024_block_num; i++) {
		//Prepare message schedule
		for (int t = 0; t < 16; t++) {
			std::string word_64 = M[i].substr(t * 8, 8);
			//std::cout << "\nword64 = " << word_64;
			unsigned long long converted=0;
			for (int i = 0; i <8; i++) {
				converted += ( ((unsigned long long) (word_64.at(i) & 0x00000000000000FF) ) << ( (7-i) *8) );
				//std::cout << "\nAddOperand = " << word_64.at(i);
				//std::cout << "\nAddoperand = " << convertToBitString((unsigned long long) word_64.at(i));
				//std::cout << "\nAdding Long = " << convertToBitString((((unsigned long long) word_64.at(i)) << ((7 - i) * 8)));
				//std::cout << "\nLongLong " << i <<" = " << convertToBitString(converted);
			}
			//std::cout << "\nLongLong F = " << convertToBitString(converted);

			w[t] = converted;
		}
		
		////Checking message
		//std::string reconstructedMessage="";
		//for (int c = 0; c < 16; c++) {
		//	unsigned long long converted = w[c];
		//	unsigned char original = 0;

		//	for (int i = 0; i <8; i++) {
		//		original = (unsigned char) (converted >> ((7 - i) * 8));
		//		reconstructedMessage += original;
		//	}
		//}

		//std::cout << "\nReconstructed Message = " << reconstructedMessage << "\n";

		for (int t = 16; t < 80; t++) {
			w[t] = SHA512_SIGMA_SMALL_1(w[t - 2]) + w[t - 7] + SHA512_SIGMA_SMALL_0(w[t-15]) + w[t-16];
		}

		//Initialize working variables to current hash value :
		unsigned long long A = h[0];
		unsigned long long B = h[1];
		unsigned long long C = h[2];
		unsigned long long D = h[3];
		unsigned long long E = h[4];
		unsigned long long F = h[5];
		unsigned long long G = h[6];
		unsigned long long H = h[7];

		//Compression Loop
		for (int t = 0; t < 80; t++) {
			unsigned long long t1 = H + SHA512_SIGMA_BIG_1(E) + SHA512_CH(E, F, G) + k[t] + w[t];
			unsigned long long t2 = SHA512_SIGMA_BIG_0(A) + SHA512_MAJ(A, B, C);
			H = G;
			G = F;
			F = E;
			E = D + t1;
			D = C;
			C = B;
			B = A;
			A = t1 + t2;
		}

		//Compute new intermediate hash value
		h[0] = A + h[0];
		h[1] = B + h[1];
		h[2] = C + h[2];
		h[3] = D + h[3];
		h[4] = E + h[4];
		h[5] = F + h[5];
		h[6] = G + h[6];
		h[7] = H + h[7];

	}

	//Concate Hash value to produce digest
	std::string digest = "";

	for (int i = 0; i < 8; i++) {
		for (int j = 7; j >=0; j--) {
			digest += (unsigned char) (h[i] >> (j*8) );
		}
	}

	delete[] M;

	return digest;
}

std::string SHA_512::convertToBitString(unsigned long long value)
{
	std::string str(64, '0');

	for (int i = 0; i < 64; i++)
	{
		if ((1ll << i) & value)
			str[63 - i] = '1';
	}

	str.insert(8, 1,' ');
	str.insert(17, 1, ' ');
	str.insert(26, 1, ' ');
	str.insert(35, 1, ' ');


	return str;
}
