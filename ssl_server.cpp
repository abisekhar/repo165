//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
#include <iostream>

using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
    SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...");
        cout << endl << "SERVER STEP 2. " << endl;    
 
        string challenge = "";    
        char buffs[5]; 
        //Reading the challenge from the ssl stream into the buffer
        int blen = SSL_read(ssl,buffs,BUFFER_SIZE);
        challenge = buffs; 

	printf("DONE.\n");
	printf("    (Challenge: \"%s\")\n", buff2hex((const unsigned char*)buffs, sizeof(buffs)).c_str());
        print_errors();

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...");
        cout << endl << "SERVER STEP 3. " << endl;    

	char mdbuf[EVP_MAX_MD_SIZE];
        //Creating a new bio object, writing the challenge to the object, and then hashing it.
        BIO *membio = BIO_new(BIO_s_mem()); 
        BIO_write(membio, buffs, blen); 
	BIO *hash = BIO_new(BIO_f_md()); 
	BIO_set_md(hash, EVP_sha1()); 
	BIO_push(hash, membio);
	int mdlen = BIO_gets(hash, mdbuf, EVP_MAX_MD_SIZE);

	string hash_string = "";
        hash_string = buff2hex((const unsigned char*)mdbuf, mdlen);
	printf("SUCCESS.\n");
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", hash_string.c_str(), mdlen);
        print_errors();

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
        cout << endl << "SERVER STEP 4. " << endl;    
	printf("4. Signing the key...");

	unsigned char buff_to[128];	
	char infileprivkey[] = "rsaprivatekey.pem";
        int siglen = 0;
        unsigned char buff_from[128];
        //Storing the hashed challenge into an unsigned char*
        memcpy(buff_from,mdbuf,sizeof(buff_from));
        //Creating a bio object for a private key, and then encrypting the challenge into buff_to using the private key
	BIO *privkey = BIO_new_file(infileprivkey, "r"); 
	RSA *rsa = PEM_read_bio_RSAPrivateKey(privkey, NULL, NULL, NULL); 
	siglen = RSA_private_encrypt(RSA_size(rsa)-11, buff_from, buff_to, rsa, RSA_PKCS1_PADDING);

        char* signature= (char*)buff_to;

         printf("DONE.\n");
         printf("    (Signed key length: %d bytes)\n", siglen);
         printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature, siglen).c_str(), siglen);
         print_errors();

    //-------------------------------------------------------------------------
	// 5. Send the signature to the( client for authentication
	printf("5. Sending signature to client for authentication...");
        cout << endl << "SERVER STEP 5. " << endl;
    
        //Flushing bio object for use later
        char bsig[BUFFER_SIZE];        
        BIO_flush(membio); 
        //Copying the signature to a buffer, and then writing the buffer to an ssl stream
        memcpy(bsig, signature, BUFFER_SIZE); 
        SSL_write(ssl, bsig , BUFFER_SIZE);

        printf("DONE.\n");
        print_errors();
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...");
        cout << endl << "SERVER STEP 6. " << endl;

        char file[BUFFER_SIZE];
        memset(file,0,sizeof(file));
        //Reading the filename from the ssl stream and writing to a buffer
        SSL_read(ssl,file,BUFFER_SIZE);

        printf("RECEIVED.\n");
        printf("    (File requested: \"%s\"\n", file);
        print_errors();

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
	//BIO_flush
	//BIO_new_file
	//BIO_puts(server, "fnf");
    //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
	//SSL_write(ssl, buffer, bytesRead);

    int bytesSent=0;
    
    printf("SENT.\n");
    printf("    (Bytes sent: %d)\n", bytesSent);

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...");

	//SSL_shutdown
    //BIO_reset
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}
