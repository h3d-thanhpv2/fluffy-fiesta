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
		std::string public_key;
		std::string private_key;
		
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
