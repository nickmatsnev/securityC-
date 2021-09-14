

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdio>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <cstdlib>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>

// made by matsnnik (Nikita Matsnev)

/*
openssl rsa -in $(PRIV_KEY) -pubout -out $(PUB_KEY) 
*/

#define FILE_READ_BUFFER_LENGTH 4096

#define MIN(a,b) ((a) < (b) ? a : b)

typedef struct header {
    int32_t i_ciph_nid;
    int32_t i_symkey_len;
    int32_t i_iv_len;
} st_header ;

int write_header(FILE * f, const EVP_CIPHER *cipher, unsigned char *enc_symkey, size_t symkey_len, unsigned char *iv, size_t iv_len);

int do_evp_seal(EVP_CIPHER_CTX *ctx, FILE *inFile, FILE *outFile);
int do_evp_open(EVP_CIPHER_CTX *ctx, FILE *inFile, FILE *outFile);


int do_evp_seal(EVP_CIPHER_CTX *ctx, FILE *inFile, FILE *outFile) {
    int res;
    int bytes_read = 0, bytes_written = 0,
        temp_len = 0;
    unsigned char inBytes[FILE_READ_BUFFER_LENGTH];
    unsigned char outBytes[FILE_READ_BUFFER_LENGTH + EVP_MAX_BLOCK_LENGTH];

    // Encryption
    while ((bytes_read = fread(inBytes, sizeof(unsigned char), FILE_READ_BUFFER_LENGTH, inFile)) > 0) {
        res = EVP_SealUpdate(ctx,  outBytes, &temp_len, inBytes, bytes_read);  // encryption of pt

        bytes_written = fwrite(outBytes, sizeof(unsigned char), temp_len, outFile);
    }
    res = EVP_SealFinal(ctx, outBytes, &temp_len); 
    bytes_written = fwrite(outBytes, sizeof(unsigned char), temp_len, outFile);
    
    return 0;
}

int do_evp_open(EVP_CIPHER_CTX *ctx, FILE *inFile, FILE *outFile) {
    int res;
    int bytes_read = 0, bytes_written = 0,
        temp_len = 0;
    unsigned char inBytes[FILE_READ_BUFFER_LENGTH];
    unsigned char outBytes[FILE_READ_BUFFER_LENGTH+EVP_MAX_BLOCK_LENGTH];

    // Decryption
    while ((bytes_read = fread(inBytes, sizeof(unsigned char), FILE_READ_BUFFER_LENGTH, inFile)) > 0) {
 		// encryption of pt
        res = EVP_OpenUpdate(ctx,  outBytes, &temp_len, inBytes, bytes_read); 

        bytes_written = fwrite(outBytes, sizeof(unsigned char), temp_len, outFile);
    }
    res = EVP_OpenFinal(ctx, outBytes, &temp_len);  
    bytes_written = fwrite(outBytes, sizeof(unsigned char), temp_len, outFile);
    
    return 0;
}

// Writes headers to the specified file
int write_header(FILE * f, const EVP_CIPHER *cipher, unsigned char *enc_symkey, size_t symkey_len, unsigned char *iv, size_t iv_len) {
	st_header h;
    h.i_ciph_nid = EVP_CIPHER_nid(cipher);
	h.i_symkey_len = symkey_len;
    h.i_iv_len = iv_len;

    if (0 >= fwrite(&h, sizeof(st_header), 1, f)) { return 0; }
	if (0 >= fwrite(enc_symkey, sizeof(unsigned char), symkey_len, f)) { return 0; }
	if (0 >= fwrite(iv, sizeof(unsigned char), iv_len, f)) { return 0; }

    return 1;
}


int main(int argc, char ** argv) {
	int ret;

	EVP_CIPHER_CTX *e_ctx = NULL;
	EVP_PKEY *e_key;
	const EVP_CIPHER *e_cipher_sym;
	unsigned char buf_iv[EVP_MAX_IV_LENGTH];
	unsigned char *buf_symkey;
	int symkey_len;

	FILE *f_key, *f_data, *f_out;

	// OpenSSL initialization
	ERR_load_crypto_strings();
	OpenSSL_add_all_ciphers();


	std::string cipher_name = "aes-256-cbc";
	std::string str_file_in, str_file_out, str_file_key;
	str_file_in = argv[1];
	str_file_key = argv[2];
	str_file_out = argv[3];
	if (argc > 4) {
		cipher_name = argv[4];
	}

	f_data = fopen(str_file_in.c_str(), "rb");

	e_ctx = EVP_CIPHER_CTX_new();

	e_cipher_sym = EVP_get_cipherbyname(cipher_name.c_str());

	f_key = fopen(str_file_key.c_str(), "rb");

	e_key = PEM_read_PUBKEY(f_key, NULL, 0, NULL);
	
	fclose(f_key);

	// create IV
	RAND_bytes(buf_iv, EVP_MAX_IV_LENGTH);

	buf_symkey = (unsigned char *) malloc(EVP_PKEY_size(e_key));

	// initialize encryption
	ret = EVP_SealInit(e_ctx, e_cipher_sym, &buf_symkey, &symkey_len, buf_iv, &e_key, 1); // 1 - number of public keys (this is like a list)

	f_out = fopen(str_file_out.c_str(), "wb");

	// write header
	if (!write_header(f_out, e_cipher_sym, buf_symkey, symkey_len, buf_iv, EVP_MAX_IV_LENGTH)) {
		perror("Error with header");
		exit(EXIT_FAILURE);
	}

	// encrypt data
	ret = do_evp_seal(e_ctx, f_data, f_out);

	fclose(f_data);
	fclose(f_out);

	EVP_PKEY_free(e_key);
	EVP_CIPHER_CTX_free(e_ctx);

	return 0;
}
