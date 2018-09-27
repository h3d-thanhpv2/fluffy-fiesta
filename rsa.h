/*
 * rsa.h
 *
 *  Created on: Sep 26, 2018
 *      Author: thanhphamvan
 */

#ifndef RSA_H_
#define RSA_H_

#include <string>

void GenKey(std::string &str_public_key, std::string &str_private_key);

bool Encrypt(const std::string rsa_public_key, const std::string source, std::string &dest);

bool Decrypt(const std::string private_key, const std::string source,
		std::string &dest);

#endif /* RSA_H_ */
