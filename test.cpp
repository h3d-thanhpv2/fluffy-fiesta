/*
 * test.cpp
 *
 *  Created on: Sep 26, 2018
 *      Author: thanhphamvan
 */

#include <iostream>
#include "rsa.h"

int main() {
	for (int i = 0; i < 100; i++) {
		std::string public_key;// = "-----BEGIN PUBLIC KEY-----\nMDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhANWHi0xRpCSCfHrdSXIKUtRkRBZEJVjV\n1112ro/Xc6ytAgMBAAE=\n-----END PUBLIC KEY-----";
		std::string private_key;// = "-----BEGIN RSA PRIVATE KEY-----\nMIGsAgEAAiEA1YeLTFGkJIJ8et1JcgpS1GREFkQlWNXXXXauj9dzrK0CAwEAAQIh\nAL3rwF9SYk/C69sQRco0GnSFBBGFrnnePOPzhcKVQFoVAhEA7M3XRez6bf7qHPjp\ntutB7wIRAObWtWwcXDBmjuuKB47l5yMCEFF+fWlpJr4YDkWuO/Bhgi0CEQDe1gvi\npmn0KzzycZekQZljAhEArE4GPX905Gs7RuUKyBZmjQ==\n-----END RSA PRIVATE KEY-----";
		
		GenKey(public_key, private_key);

		std::cout << public_key << std::endl;
		std::cout << private_key << std::endl;
		
		std::string raw = "abcxyz";
		std::string encrypt;
		std::string decrypt;

			if (Encrypt(public_key, raw, encrypt)) {
				std::cout << "Encrypted: " << encrypt << std::endl;

				if (Decrypt(private_key, encrypt, decrypt)) {
					std::cout << "Decrypted: " << decrypt << std::endl;
				}
			}
	}


	return 0;
}
