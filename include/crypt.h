#pragma once

#include <array>
#include <algorithm>


namespace crypt
{
	namespace func
	{
		template <typename T>
		constexpr void swap(T& a, T& b)
		{
			T temp = a;
			a = b;
			b = temp;
		}

		constexpr char vigenere_char_encrypt(char c, char key)
		{
			if (c >= 'A' && c <= 'Z')
			{
				return 'A' + (c - 'A' + (key - 'A')) % 26;
			}
			else if (c >= 'a' && c <= 'z')
			{
				return 'a' + (c - 'a' + (key - 'a')) % 26;
			}
			else
			{
				return c; 
			}
		}
		constexpr char vigenere_char_decrypt(char c, char key)
		{
			if (c >= 'A' && c <= 'Z')
			{
				return 'A' + (c - 'A' - (key - 'A') + 26) % 26;
			}
			else if (c >= 'a' && c <= 'z')
			{
				return 'a' + (c - 'a' - (key - 'a') + 26) % 26;
			}
			else
			{
				return c; 
			}
		}

		//constexpr char affine_encrypt(char c, int a, int b, int mod = 26) 
		//{
		//	char base{};
		//	if (c >= 'A' && c <= 'Z')
		//	{
		//		base = 'A';
		//	}
		//	else if (c >= 'a' && c <= 'z') 
		//	{
		//		base = 'a';
		//	}
		//	else 
		//	{
		//		return c; 
		//	}

		//	int x = c - base;
		//	int encrypted = (a * x + b) % mod;
		//	if (encrypted < 0) encrypted += mod;
		//	return static_cast<char>(encrypted + base);
		//}
		//constexpr int mod_inverse(int a, int m) 
		//{
		//	int t = 0, new_t = 1;
		//	int r = m, new_r = a;
		//	while (new_r != 0) 
		//	{
		//		int quotient = r / new_r;
		//		t = t - quotient * new_t;
		//		func::swap(t, new_t);
		//		r = r - quotient * new_r;
		//		func::swap(r, new_r);
		//	}
		//	if (r > 1) return 0; 
		//	if (t < 0) t = t + m;
		//	return t;
		//}
		//constexpr char affine_decrypt(char c, int a, int b, int mod = 26) 
		//{
		//	char base{};
		//	if (c >= 'A' && c <= 'Z') {
		//		base = 'A';
		//	}
		//	else if (c >= 'a' && c <= 'z') {
		//		base = 'a';
		//	}
		//	else {
		//		return c; 
		//	}

		//	int a_inv = mod_inverse(a, mod);

		//	if (a_inv == 0) 
		//		return c; 

		//	int y = c - base;
		//	int decrypted = (a_inv * (y - b + mod)) % mod;
		//	if (decrypted < 0) decrypted += mod; 
		//	return static_cast<char>(decrypted + base);
		//}

		/*~~~~~~~~~~~~~RSA~~~~~~~~~~~~~~~*/
		//constexpr long int mod_exp(long int base, long int exp, long int mod) 
		//{
		//	long int result = 1;
		//	base = base % mod;
		//	while (exp > 0) 
		//  {
		//		if (exp % 2 == 1) 
		//		{
		//			result = (result * base) % mod;
		//		}
		//		exp = exp >> 1;
		//		base = (base * base) % mod;
		//	}
		//	return result;
		//}

		//constexpr long int RSA_encrypt_char(char ch, long int e, long int n) 
		//{
		//	return mod_exp(static_cast<long int>(static_cast<unsigned char>(ch)), e, n);
		//}

		//constexpr char RSA_decrypt_char(long int encrypted_ch, long int d, long int n) 
		//{
		//	return static_cast<char>(mod_exp(encrypted_ch, d, n));
		//}
	}
	
	// XOR

	template<std::size_t len, std::size_t keyLen>
	constexpr std::array<char, len> xor_encrypt(const char(&input)[len], const char(&key)[keyLen])
	{
		std::array<char, len> output{};
		for (std::size_t i = 0; i < len; ++i) 
		{
			output[i] = input[i] ^ key[i % keyLen];
		}
		return output;
	}

	template<std::size_t len, std::size_t keyLen>
	constexpr std::array<char, len> xor_decrypt(const char(&input)[len], const char(&key)[keyLen])
	{
		xor_encrypt(input, key);
	}

	
	//Caesar cipher, each letter is replaced by a letter shifted a fixed number of positions
	template<std::size_t len>
	constexpr std::array<char, len> cesar_encrypt(const char(&input)[len], int shift) 
	{
		auto shift_char = [](char c, int shift) -> char
		{
			if (c >= 'A' && c <= 'Z')
			{
				return 'A' + (c - 'A' + shift + 26) % 26;
			}
			else if (c >= 'a' && c <= 'z')
			{
				return 'a' + (c - 'a' + shift + 26) % 26;
			}
			return c;
		};

		std::array<char, len> output = {};
		for (std::size_t i = 0; i < len - 1; ++i) 
		{ 
			output[i] = shift_char(input[i], shift);
		}

		return output;
	}

	template<std::size_t len>
	constexpr std::array<char, len> cesar_decrypt(const char(&input)[len], int shift)
	{
		return cesar_encrypt(input, -shift);
	}

	//Caesar cipher with a fixed shift of 13 positions
	template<std::size_t len>
	constexpr std::array<char, len> rot13_encrypt(const char(&input)[len])
	{
		return cesar_encrypt(input, 13);
	}

	template<std::size_t len>
	constexpr std::array<char, len> rot13_decrypt(const char(&input)[len])
	{
		return cesar_encrypt(input, -13);
	}

	// Simple Substitution Cipher, each letter is replaced by another letter from a predetermined alphabet.
	template<std::size_t len>
	constexpr std::array<char, len> subCipher_encrypt(const char(&input)[len], std::array<char, 26> substitutionTable)
	{
		std::array<char, len> output = {};
		for (std::size_t i = 0; i < len - 1; ++i) 
		{
			if (input[i] >= 'A' && input[i] <= 'Z')
			{
				output[i] = substitutionTable[input[i] - 'A'];
			}
			else if (input[i] >= 'a' && input[i] <= 'z')
			{
				output[i] = substitutionTable[input[i] - 'a'] + ('a' - 'A');
			}
			else
			{
				output[i] = input[i];
			}
		}

		return output;
	}

	template<std::size_t len>
	constexpr std::array<char, len> subCipher_decrypt(const char(&input)[len], std::array<char, 26> substitutionTable)
	{
		return subCipher_encrypt(input, substitutionTable);
	}


	//Vigenere Cipher, multiple uses of the Caesar cipher using a keyword
	template<std::size_t len, std::size_t keyLen>
	constexpr std::array<char, len> vigenere_encrypt(const char(&input)[len], const char(&key)[keyLen])
	{

		std::array<char, len> result = {};
		for (size_t i = 0, j = 0; i < len - 1; ++i)
		{ 
			result[i] = func::vigenere_char_encrypt(input[i], key[j]);

			
			j = (j + 1) % keyLen; 
			
		}
		return result;
	}

	template<std::size_t len, std::size_t keyLen>
	constexpr std::array<char, len> vigenere_decrypt(const char(&input)[len], const char(&key)[keyLen])
	{
		std::array<char, len> result = {};
		for (size_t i = 0, j = 0; i < len - 1; ++i) 
		{
			result[i] = func::vigenere_char_decrypt(input[i], key[j]);
			j = (j + 1) % keyLen;
		}
		return result;
	}

	//template<std::size_t len>
	//constexpr std::array<char, len> affine_encrypt(const char(&input)[len], int a, int b, int mod = 26)
	//{
	//	std::array<char, len> encrypted{};
	//	for (std::size_t i = 0; i < len; ++i) 
	//	{
	//		encrypted[i] = func::affine_encrypt(input[i], a, b, mod);
	//	}
	//	return encrypted;
	//}

	//template<std::size_t len>
	//constexpr std::array<char, len> affine_decrypt(const char(&input)[len], int a, int b, int mod = 26) 
	//{
	//	std::array<char, len> decrypted{};
	//	for (std::size_t i = 0; i < len; ++i) 
	//	{
	//		decrypted[i] = func::affine_decrypt(input[i], a, b, mod);
	//	}
	//	return decrypted;
	//}

	
	//RC4, generates a pseudo-random keystream which is then used for XOR
	template<std::size_t len, std::size_t keyLen>
	constexpr std::array<char, len> rc4_encrypt(const char(&input)[len], const char(&key)[keyLen])
	{
		// key-scheduling algorithm (KSA)
		std::array<unsigned char, 256> subTable = {};
		for (std::size_t i = 0; i < 256; i++)
		{
			subTable[i] = static_cast<unsigned char>(i);
		}

		std::size_t k = 0, m = 0;
		for (std::size_t i = 0; i < 256; ++i)
		{
			k = (k + subTable[i] + static_cast<unsigned char>(key[i % keyLen])) % 256;
			func::swap(subTable[i], subTable[k]);
		}

		// pseudo-random generation algorithm (PRGA)
		std::array<char, len> output{};
		k = 0;

		for (std::size_t i = 0; i < len - 1; i++)
		{
			m = (m + 1) % 256;
			k = (k + subTable[m]) % 256;
			func::swap(subTable[m], subTable[k]);

			unsigned char pseudo = subTable[(subTable[m] + subTable[k]) % 256];
			output[i] = input[i] ^ pseudo;
		}

		return output;
	}


	template<std::size_t len, std::size_t keyLen>
	constexpr std::array<char, len> rc4_decrypt(const char(&input)[len], const char(&key)[keyLen])
	{
		return rc4_encrypt(input, key);
	}
	
	//template <std::size_t N>
	//constexpr void rsa_encrypt(const char(&input)[N], long int e, long int n, long int(&encrypted)[N]) 
	//{
	//	for (std::size_t i = 0; i < N - 1; ++i) {
	//		encrypted[i] = func::RSA_encrypt_char(input[i], e, n);
	//	}
	//	encrypted[N - 1] = 0; // End of data marker
	//}

	//template <std::size_t N>
	//constexpr void rsa_decrypt(const long int(&encrypted)[N], long int d, long int n, char(&decrypted)[N]) 
	//{
	//	for (std::size_t i = 0; i < N - 1; ++i) {
	//		decrypted[i] = func::RSA_decrypt_char(encrypted[i], d, n);
	//	}
	//	decrypted[N - 1] = '\0'; // Null-terminate
	//}
}