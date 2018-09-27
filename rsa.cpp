#include "rsa.h"

#include <iostream>
#include <malloc.h>
#include <memory>
#include <cassert>
#include <cstring>
// #include <filesystem>  // for using std::filesystem::temp_directory_path
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

#include "base64.h"

#define PRIVATE_KEY_BITS 256
#define PADDING RSA_PKCS1_PADDING
#define DEBUG 1

// namespace filesystem = std::filesystem;

using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BIGNUM_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using BIO_MEM_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using BIO_MEM_BUF_ptr = std::unique_ptr<BUF_MEM, decltype(&::BUF_MEM_free)>;
using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;  // redeclare

void GenKey(std::string &str_public_key, std::string &str_private_key){
	int rc;

	RSA_ptr rsa (RSA_new(), ::RSA_free);  // openssl rsa pointer
	BIGNUM_ptr bn(BN_new(), ::BN_free);  // bignum

	int bits = PRIVATE_KEY_BITS;
	unsigned long e = RSA_F4;

	rc = BN_set_word(bn.get(), e);
	assert(rc == 1);

	// Generate RSA key
	rc = RSA_generate_key_ex(rsa.get(), bits, bn.get(), NULL);
	assert(rc == 1);

	// Convert RSA to Private Key
	EVP_KEY_ptr public_key(EVP_PKEY_new(), ::EVP_PKEY_free);
	rc = EVP_PKEY_set1_RSA(public_key.get(), rsa.get());
	assert(rc == 1);

	// Create 2 in-memory BIO for public key and private key
	BIO_MEM_ptr public_key_bio(BIO_new(BIO_s_mem()), ::BIO_free);
	BIO_MEM_ptr private_key_bio(BIO_new(BIO_s_mem()), ::BIO_free);
	// BIO_MEM_ptr public_key_bio(BIO_new(BIO_s_mem()), ::BIO_free);
	// BIO_MEM_ptr private_key_bio(BIO_new(BIO_s_mem()), ::BIO_free);

	// Write Public Key in Traditional PEM
	rc = PEM_write_bio_PUBKEY(public_key_bio.get(), public_key.get());
	assert (rc == 1);

	// Write Private Key in Traditional PEM
	rc = PEM_write_bio_RSAPrivateKey(private_key_bio.get(), rsa.get(), NULL, NULL, 0, NULL, NULL);
	assert (rc == 1);

	// BIO_flush(public_key_bio.get());
	// BIO_flush(private_key_bio.get());
	
	// BIO_MEM_BUF_ptr public_key_buff(BUF_MEM_new(), ::BUF_MEM_free);
	// BIO_MEM_BUF_ptr private_key_buff(BUF_MEM_new(), ::BUF_MEM_free);
	// BUF_MEM * public_key_bptr = nullptr;
	// BUF_MEM * private_key_bptr = nullptr;

	// BIO_get_mem_ptr(public_key_bio.get() , &public_key_bptr);
	// BIO_get_mem_ptr(private_key_bio.get(), &private_key_bptr);

	// const BUF_MEM &pkey = *(public_key_buff.get());
	// const BUF_MEM &key = *(private_key_buff.get());

	// std::cout << public_key_buff.get()->data << std::endl;

	size_t pkey_length = BIO_pending(public_key_bio.get());
	size_t key_length = BIO_pending(private_key_bio.get());

	std::unique_ptr<char> pkey_buff((char *) malloc(pkey_length + 1));
	std::unique_ptr<char> key_buff((char *) malloc(key_length + 1));

	// memcpy(pkey_buff.get(), public_key_bptr->data, public_key_bptr->length - 1);
	// memcpy(key_buff.get(), private_key_bptr->data, private_key_bptr->length - 1);  // dunno why there is always an extra '-' at the end

	BIO_read(public_key_bio.get(), pkey_buff.get(), pkey_length);
	BIO_read(private_key_bio.get(), key_buff.get(), key_length);

	// NULL Terminator
	pkey_buff.get()[pkey_length] = '\0';
	key_buff.get()[key_length] = '\0';

	str_public_key.assign(pkey_buff.get(), pkey_length);
	str_private_key.assign(key_buff.get(), key_length);

	// str_public_key.assign((public_key_buff.get()->data ? public_key_buff.get()->data : ""), (public_key_buff.get()->data ? public_key_buff.get()->length : 0));
	// str_private_key.assign((private_key_buff.get()->data ? private_key_buff.get()->data : ""), (private_key_buff.get()->data ? private_key_buff.get()->length : 0));

#if DEBUG
	std::cout << "Public key buffer length: " << pkey_length << std::endl;
	std::cout << "Private key buffer length: " << key_length << std::endl;
#endif

}

bool Encrypt(const std::string rsa_public_key, const std::string source,
		std::string &dest) {
	/*
	 * @Param: 
	 * 		rsa_public_key: Traditional PEM Public Key
	 * 		source: std::string need to encrypted
	 * @Output: 
	 * 		dest: Encrypted std::string
	 * */
	size_t rsa_public_key_len = rsa_public_key.size()
			* sizeof(std::string::value_type);
	size_t msg_size = source.size() * sizeof(std::string::value_type);

	// LOAD PUBLIC KEY FROMS STRING USING OpenSSL's API
	BIO_MEM_ptr bio(BIO_new(BIO_s_mem()), ::BIO_free); // I/O abstraction
	// BIO_new_mem_buf((void*) rsa_public_key.c_str(), -1)
	BIO_write(bio.get(), rsa_public_key.c_str(), rsa_public_key_len);
	BIO_set_flags(bio.get(), BIO_FLAGS_BASE64_NO_NL);
	// Read public key
	RSA_ptr _public_key(PEM_read_bio_RSA_PUBKEY(bio.get(), NULL, 0, NULL),
			::RSA_free);
	if (!_public_key.get()) {
		printf(
			"ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n",
			ERR_error_string(ERR_get_error(), NULL)
		);
		return false;
	}
	int rsa_len = RSA_size(_public_key.get());

	std::unique_ptr<unsigned char> encrypted((unsigned char *) malloc(rsa_len));
	size_t encrypted_data_len = RSA_public_encrypt(msg_size,
			(const unsigned char *) source.c_str(), encrypted.get(),
			_public_key.get(), PADDING);
	if (encrypted_data_len == -1) {
		printf(
			"ERROR: RSA_public_encrypt: %s\n",
			ERR_error_string(ERR_get_error(), NULL)
		);
		return false;
	}

	// To base 64
	int ascii_base64_encrypted_len;
	std::unique_ptr<char> ascii_base64_encrypted(
			base64(encrypted.get(), encrypted_data_len,
					&ascii_base64_encrypted_len));

	dest.assign(ascii_base64_encrypted.get(), ascii_base64_encrypted_len);

	return true;
}

bool Decrypt(const std::string private_key, const std::string source,
		std::string &dest) {
	// Code ngu người những vẫn chạy, must be magic
	int bin_encrypted_len;
	std::unique_ptr<unsigned char> bin_encrypted(
			unbase64(source.c_str(), source.length(), &bin_encrypted_len));

	// LOAD PRIVATE KEY FROM STRING USING OpenSSL API
	BIO_MEM_ptr bio(BIO_new_mem_buf((void*) private_key.c_str(), -1),
			::BIO_free);
	RSA_ptr _private_key(PEM_read_bio_RSAPrivateKey(bio.get(), NULL, 0, NULL),
			::RSA_free);

	if (!_private_key.get()) {
		printf(
				"ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
		assert(false);
		return false;
	}

	size_t rsa_len = RSA_size(_private_key.get());
	std::unique_ptr<unsigned char> bin_decrypted(
			(unsigned char *) malloc(rsa_len));

	size_t decrypted_data_len = RSA_private_decrypt(rsa_len,
			bin_encrypted.get(), bin_decrypted.get(), _private_key.get(),
			PADDING);
	if (decrypted_data_len == -1) {
		printf("ERROR: RSA_private_decrypt: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
		return false;
	}

	dest.assign(reinterpret_cast<char*>(bin_decrypted.get()), decrypted_data_len);

	return true;
}
