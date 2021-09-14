#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <vector>
#include <iostream>

std::vector<std::string> answers;
void getString(std::string s, int digitsLeft )
{
    if( digitsLeft == 0 )
        answers.push_back( s );
    else
    {
        for(int i = 32; i<=126; ++i){
            getString( s + (char)(i), digitsLeft - 1 );
        }
    }
}


void printCurrentHash(unsigned char hash[64], int length){
    for(int i = 0; i< length; ++i){
        printf("%02x", hash[i]);
    }
    printf("\n\n");
}

int hash(const char* str, unsigned char hash[64]){
    int res;
	/* Find out which hash function should be used */
    char hashFunction[] = "sha256";
    EVP_MD_CTX *ctx;// structure 
    const EVP_MD *type; //the type of hash function used 
    int length;

   
    type = EVP_get_digestbyname(hashFunction);
    if(!type) {
    printf("Hash %s does not exist.\n", hashFunction);
    exit(1);
    }

    ctx = EVP_MD_CTX_create();
    if(ctx == NULL) exit(2);

    res = EVP_DigestInit_ex(ctx, type, NULL); // context setup for our hash type
    if(res != 1) exit(3);
    res = EVP_DigestUpdate(ctx, str, strlen(str)); // feed the message in
    if(res != 1) exit(4);
    res = EVP_DigestFinal_ex(ctx, hash, (unsigned int *) &length); // get the hash
    
    if(res != 1) exit(5);

    EVP_MD_CTX_destroy(ctx); 
    return length;
    
}


std::string unhash(int amountOfOnes){
    unsigned char cur_hash[64];
    int cur_len = 0;
    int i = 1;
    
    while(1){
        getString("", i);
        for(auto str: answers){
            cur_len = hash(str.c_str(), cur_hash);
            int len = 0;
            for(int j = 0; j < amountOfOnes; j ++){
            	if(cur_hash[j] == (unsigned char) 0x11){
            		len++;
				}
			}
			if(len == amountOfOnes){
				std::cout << "This is hash code:" << std::endl;
                	printCurrentHash(cur_hash, 64);
                    return str;
            }
        }
        ++i;
    }
}



int main(int argc, char *argv[]){
	/* Initialize the OpenSSL hash function*/
    OpenSSL_add_all_digests();
    int givenOnes = 0;
  	if(argc < 2){  
      	printf("No argument passed through command line.\n");   
      	return 0;
   	}  
   	else{  
 		givenOnes = atoi(argv[1]);
   	}  
   	if(givenOnes > 2){
   		if(givenOnes%2 == 0){
   			givenOnes/=2;
		   }else{
		   	givenOnes/=2;
		   	givenOnes++;
		   }
	   }else{
	   	givenOnes = 2;
	   }
    std::string res = unhash(givenOnes);
	std::cout << "This is the message:" << std::endl;
    for(auto i: res){
        std::cout << std::hex << (unsigned) i << " ";
    }
    std::cout << std::endl;
    exit(0);
}