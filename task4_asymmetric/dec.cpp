#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdio>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstdlib>
#include <cstring>


// done by matsnnik (Nikita Matsnev)


#define FREAD_BUF_LEN 4096

#define MIN(a,b) ((a) < (b) ? a : b)

typedef struct header {
    int32_t i_ciph_nid;
    int32_t i_symkey_len;
    int32_t i_iv_len;
} st_header ;


int do_evp_seal(EVP_CIPHER_CTX *ctx, FILE *inFile, FILE *outFile);
int do_evp_open(EVP_CIPHER_CTX *ctx, FILE *inFile, FILE *outFile);

void print_openssl_error_and_fail(bool do_fail = true);

int do_evp_seal(EVP_CIPHER_CTX *ctx, FILE *inFile, FILE *outFile) {
    int res;
    int bytes_read = 0, bytes_written = 0,
        temp_len = 0;
    unsigned char inBytes[FREAD_BUF_LEN];
    unsigned char outBytes[FREAD_BUF_LEN+EVP_MAX_BLOCK_LENGTH];

    // Encryption
    while ((bytes_read = fread(inBytes, sizeof(unsigned char), FREAD_BUF_LEN, inFile)) > 0) {
        res = EVP_SealUpdate(ctx,  outBytes, &temp_len, inBytes, bytes_read);  // encryption of pt
     
        bytes_written = fwrite(outBytes, sizeof(unsigned char), temp_len, outFile);
   
    }

    res = EVP_SealFinal(ctx, outBytes, &temp_len);  // get the remaining ct
    bytes_written = fwrite(outBytes, sizeof(unsigned char), temp_len, outFile);
    
    return 0;
}

int do_evp_open(EVP_CIPHER_CTX *ctx, FILE *inFile, FILE *outFile) {
    int res;
    int bytes_read = 0, bytes_written = 0,
        temp_len = 0;
    unsigned char inBytes[FREAD_BUF_LEN];
    unsigned char outBytes[FREAD_BUF_LEN+EVP_MAX_BLOCK_LENGTH];

    // Decryption
    while ((bytes_read = fread(inBytes, sizeof(unsigned char), FREAD_BUF_LEN, inFile)) > 0) {
        res = EVP_OpenUpdate(ctx,  outBytes, &temp_len, inBytes, bytes_read);  // encryption of pt

        bytes_written = fwrite(outBytes, sizeof(unsigned char), temp_len, outFile);
    }
 
    res = EVP_OpenFinal(ctx, outBytes, &temp_len);  // get the remaining ct
    bytes_written = fwrite(outBytes, sizeof(unsigned char), temp_len, outFile);

    return 0;
}

// Reads the file header and populates the cipher, also allocates the buffers and returns the length.
int read_header(FILE * f, const EVP_CIPHER **cipher, unsigned char **enc_symkey, size_t *symkey_len, unsigned char **iv, size_t *iv_len) {
    st_header h;

    if (0 >= fread(&h, sizeof(st_header), 1, f)) { return 0; }
	*symkey_len = h.i_symkey_len;
    *iv_len = h.i_iv_len;
    // allocate space for encrypted sym key and IV
	*enc_symkey = (unsigned char *) malloc(*symkey_len);
    
	
    *iv = (unsigned char *) malloc(*iv_len);
   
   
	// read the symkey and IV
	if (0 >= fread(*enc_symkey, sizeof(unsigned char), *symkey_len, f)) { return 0; }
	if (0 >= fread(*iv, sizeof(unsigned char), *iv_len, f)) { return 0; }

	// initialize the symmetric cipher
	*cipher = EVP_get_cipherbynid(h.i_ciph_nid);

    return 1;
}


void print_openssl_error_and_fail(bool do_fail) {
	std::cerr << "OpenSSL error: ";
	ERR_print_errors_fp(stderr);
    if (do_fail) {
	    exit(EXIT_FAILURE);
    }
}



int main(int argc, char ** argv) {
	int ret;

	EVP_CIPHER_CTX *e_ctx = NULL;
	EVP_PKEY *e_key;
	const EVP_CIPHER *e_cipher_sym;
	unsigned char *buf_symkey;
	unsigned char *buf_iv;
	size_t symkey_len;
	size_t iv_len;


	FILE *f_key, *f_data, *f_out;

	// OpenSSL initialization
	ERR_load_crypto_strings();
	OpenSSL_add_all_ciphers();

	std::string str_file_in, str_file_out, str_file_key;

	str_file_in = argv[1];
	str_file_key = argv[2];
	str_file_out = argv[3];

	// Open input file
	f_data = fopen(str_file_in.c_str(), "rb");

	//error while opening
	if (f_data == NULL) {
		exit(EXIT_FAILURE);
	}


	//failed initialisation of the context
	e_ctx = EVP_CIPHER_CTX_new();
	if (e_ctx == NULL) {
		exit(EXIT_FAILURE);
	}

	// Open and read the keys
	f_key = fopen(str_file_key.c_str(), "rb");

	//error with the key
	if (f_key == NULL) {
		exit(EXIT_FAILURE);
	}	


	e_key = PEM_read_PrivateKey(f_key, NULL, 0, NULL);


	if (e_key == NULL) {
		print_openssl_error_and_fail();
	}
	fclose(f_key);

	// CRYPT
	// read header
	if (!read_header(f_data, &e_cipher_sym, &buf_symkey, &symkey_len, &buf_iv, &iv_len)) {
		perror("Error while reading header");
		exit(EXIT_FAILURE);
	}

	// initialize open
	ret = EVP_OpenInit(e_ctx, e_cipher_sym, buf_symkey, symkey_len, buf_iv, e_key);
    if(ret != 1) {
		print_openssl_error_and_fail();
	}
	
	// Open output file
	f_out = fopen(str_file_out.c_str(), "wb");
	if (NULL == f_out) {
		perror("Error while opening output file");
		exit(EXIT_FAILURE);
	}	

	// unseal (open) data
	ret = do_evp_open(e_ctx, f_data, f_out);
	if (0 != ret) {
		print_openssl_error_and_fail();
	}

	fclose(f_data);
	fclose(f_out);

	EVP_PKEY_free(e_key);
	EVP_CIPHER_CTX_free(e_ctx);

	free(buf_symkey);
	free(buf_iv);

	return 0;
}
