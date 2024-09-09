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

		//affine
		constexpr int find_id(char c) 
		{
			if (c >= 'A' && c <= 'Z') 
				return c - 'A';
			if (c >= 'a' && c <= 'z') 
				return c - 'a';  
			return -1;  
		}
		
		//affine
		constexpr char find_char(int id, bool is_upper) {
			return is_upper ? 'A' + id : 'a' + id;
		}

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

	//Affine cipher
	template<std::size_t len>
	constexpr std::array<char, len> affine_encrypt(const char(&input)[len], int a, int b, int mod = 26)
	{
		std::array<char, len> result{};
		
		for (std::size_t i = 0; i < len - 1; ++i) 
		{ 
			char c = input[i];
			bool is_upper = (c >= 'A' && c <= 'Z');
			bool is_lower = (c >= 'a' && c <= 'z');

			if (is_upper || is_lower) 
			{
				int id = func::find_id(c);

				if (id != -1) 
				{
					
					int encrypted_id = (a * id + b) % mod;
					result[i] = func::find_char(encrypted_id, is_upper);
				}
			}
			else 
			{
				
				result[i] = c;
			}
		}

		return result;
	}

	template<std::size_t len>
	constexpr std::array<char, len> affine_decrypt(const char(&input)[len], int a, int b, int mod = 26) 
	{
		std::array<char, len> result{};

		int modInverse = 0;
		int a_mod = a % mod;
		for (int x = 1; x < mod; ++x) 
		{
			if ((a_mod * x) % mod == 1)
			{
				modInverse = x;
			}
		}

		for (std::size_t i = 0; i < len - 1; ++i)
		{
			char c = input[i];
			bool is_upper = (c >= 'A' && c <= 'Z');
			bool is_lower = (c >= 'a' && c <= 'z');

			if (is_upper || is_lower)
			{
				int id = func::find_id(c);

				if (id != -1)
				{
					int encrypted_id = (modInverse * (id + mod - b)) % mod;
					result[i] = func::find_char(encrypted_id, is_upper);
				}
			}
			else
			{
				result[i] = c;
			}
		}

		return result;
	}

	
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