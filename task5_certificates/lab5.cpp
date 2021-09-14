#include <cstring>
#include <iostream>
#include <stdio.h>
#include <cstdlib>
#include <string>
#include <strings.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

// by Nick Matsnev
using namespace std;

int main() {
	
	//declare host name and the path 
     string hostName = "old.fit.cvut.cz";
     string getPath = "/en/student/forms";

	//port number for TCP connection
    int portNum = 443;
    
    /*
    from <netdb.h>
struct  hostent {
     char *  h_name;     
     char ** h_aliases; 
     int     h_addrtype;  
     int     h_length;    
     char ** h_addr_list;
};
    */
	struct hostent *he = gethostbyname("www.fit.cvut.cz");
     string ipAddress = inet_ntoa(*((struct in_addr*)
            he->h_addr_list[0]));
	
    int sockfd;
    struct sockaddr_in servaddr;

    sockfd=socket(AF_INET,SOCK_STREAM,0);

    bzero(&servaddr,sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr=inet_addr(ipAddress.c_str()); //ip address fit cvut cz
    servaddr.sin_port=htons(portNum); // port 443

    int res;
    if (0 != (res = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)))) {
         cout << "Failed to connect."<< endl;
        return 1;
    }

    SSL_library_init();

    SSL_CTX* ctx;
    ctx = SSL_CTX_new(SSLv23_client_method());
    if(ctx == nullptr){
         cout << "Failed to create context."<< endl;
        return 1;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
    
    
    //we get the path
    long int verification;
	verification = SSL_CTX_set_default_verify_paths(ctx);
	
	
    SSL* ssl;
    ssl = SSL_new(ctx);
    if(ssl == nullptr){
         cout << "Failed to create SSL Mode context."<< endl;
        return 2;
    }
    if(SSL_set_tlsext_host_name(ssl, hostName.c_str()) != 1){
         cout << "Failed to set a host name."<< endl;
        return 3;
    }
    if(SSL_set_fd(ssl, sockfd) != 1){
         cout << "Failed to set socket."<< endl;
        return 4;
    }
    if(SSL_connect(ssl) != 1){
         cout << "Failed to establish connection."<< endl;
        return 5;
    }

    X509* certificate = SSL_get_peer_certificate(ssl);

    if(certificate == nullptr){
         cout << "Failed to get a certificate."<< endl;
        return 6;
    }
	//we verify  the path
	long int after_verification;
	after_verification = SSL_get_verify_result(ssl);
	
	cout << "Verification results (0 - succeeded or no peer presented. 1 - error): " << after_verification << endl;
	cout << "Cipher: " << SSL_get_cipher_name(ssl) << endl;
	
	//write certificate info in the file
    FILE *certificateInfo = fopen("certificate.pem", "w");
    PEM_write_X509(certificateInfo, certificate);

	//initialization of BIO method function
	//Data written to a memory BIO is stored 
	//in a BUF_MEM structure which is extended
	// as appropriate to accommodate the stored data.
    BIO* bio = BIO_new(BIO_s_mem());

	//setting the subject name of our certificate
	//this pointer is an internal pointer which must not be freed
    X509_NAME *subject = X509_get_subject_name(certificate);
    //prints readable version of X509 name to the BIO
    //third argument is used for multiline formts for space indention
    //fourth argument is a flags parameter serving for
    //customization of the out
    X509_NAME_print_ex(bio, subject, 0, 0);

    char certificateStr[4096]={0};
	//BIO read places data from BIO to buffer
    BIO_read(bio, certificateStr, 4095);
    //frees our BIO
    BIO_free(bio);
    
	//printing the result
     cout << certificateStr <<  endl;

    
     stringstream ss;
     ss << "GET "<<  getPath <<" HTTP/1.1" << "\r\n"
        << "Host: "<< hostName<<"\r\n"
        << "Connection: close\r\n"
        << "\r\n\r\n";
        
     string request = ss.str();
    
    if(SSL_write(ssl, request.c_str(), request.size()+1) <0){
         cout << "Failed to send request"<< endl;
        return 5;
    }
    
    char payload[1024] = {0};
    
    int responseResult;
    
     ofstream output("source.txt");
    
    while((responseResult = SSL_read(ssl, payload, 1024)) > 0){
        payload[responseResult] = '\0';
        output << payload<< endl;
    }
    
    output.close();
    
    //shutdown
    SSL_shutdown(ssl);
    shutdown(sockfd, SHUT_RDWR);

    //free
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
