//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
#include <iostream>
using namespace std;

#include <openssl/rand.h>
#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...");
        cout << endl << "CLIENT STEP 2. " << endl;        
        string randomNumber="31337";
        unsigned char buffs[5];
        RAND_bytes(buffs,sizeof(buffs));
        //Copying the randomNumber into a buffer of size BUFFER_SIZE = 1024
        //memcpy(buffs, randomNumber.c_str(), BUFFER_SIZE);
        //Writing the buffer into the ssl stream 
        SSL_write(ssl, buffs, sizeof(buffs)); 
        printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", buff2hex(((const unsigned char*)buffs), sizeof(buffs)).c_str());

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");
        cout << endl << "CLIENT STEP 3a. " << endl;

        char signkey[BUFFER_SIZE]; 
        int len = 5;
        //Reading the signed key from the ssl stream into a buffer
        SSL_read(ssl,signkey,BUFFER_SIZE);

        printf("RECEIVED.\n");
        printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signkey, len).c_str(), len);
        print_errors();

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");
        cout << endl << "CLIENT STEP 3b. " << endl;
        
        
	char infilepubkey[] = "rsapublickey.pem";
        unsigned char buff_to[BUFFER_SIZE];
        //Creating a new bio object, then writing the signed key to it.
        //Putting the rsa encrypted value into our BIO pubkey, and then decrypting the signkey, thus retrieving the SHA1 hash value from earlier, and storing that into buff_to
	BIO *membio = BIO_new(BIO_s_mem());  
   	int r = BIO_write(membio, signkey, BUFFER_SIZE); 
	BIO *pubkey = BIO_new_file(infilepubkey, "r");
	RSA *rsa = PEM_read_bio_RSA_PUBKEY(pubkey, NULL, NULL , NULL);
	RSA_public_decrypt(RSA_size(rsa), (const unsigned char* )signkey, buff_to, rsa, RSA_PKCS1_PADDING);
        //Generated Key contains the signature for the SHA1 hash
	string generated_key = buff2hex((const unsigned char* ) signkey, 20);
        //Decrypted Key contains the decrypted signature, which is the SHA1 hash
        string decrypted_key = buff2hex((const unsigned char* ) buff_to, 20); 

	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", generated_key.c_str());
	printf("    (Decrypted key: %s)\n", decrypted_key.c_str());
	BIO_free(pubkey);
        print_errors();

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");
        cout << endl << "CLIENT STEP 4. " << endl;
	PAUSE(2);
        //Flushing the bio object to allow use of it later
        BIO_flush(membio);
        //Storing filename from terminal into a string
        string fn = filename;
        BIO_puts(membio,filename);
        //Writing the filename into the ssl stream for server to know what file to read
        SSL_write(ssl, filename, fn.size());

        printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);
        print_errors();
    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...");
        cout << endl << "CLIENT STEP 5. " << endl;

        string receive = "outfile.txt";
        BIO *outfile = BIO_new_file(receive.c_str(), "w");
        char ofile[BUFFER_SIZE];
        int actualRead; 
        int read_len;

        while((actualRead = SSL_read(ssl,ofile,1)) >= 1)
        {
          BIO_write(outfile, ofile , actualRead);
          cout << ofile[0];   
        }

	printf("FILE RECEIVED.\n");
        print_errors();
    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	//Shutting down the ssl stream
	SSL_shutdown(ssl);
	
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
