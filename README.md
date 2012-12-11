repo165
=======

Abilasch Sekhar
SID: 860897073
asekh001@ucr.edu

I am going to upload the ssl_client.cpp, ssl_server.cpp, and the README.md, because the private and public key files were given, as well as the utils.h, so I'm assuming you will have those files when running our code.

NOTE: I output the contents of the filename passed in to terminal, to a new file called "outfile.txt" through client side.

To compile the code, type "make" in the console.
To run the code,
From client side on terminal, type the following: client serveraddress:portnumber filename
From server side on terminal, type the following: server portnumber

General explanation of my code:
After establishing an SSL connection to the server (which was already implemented for me), I generated a random number of size 5 bytes for purposes of avoiding long length of bytes. 
1. I used the standard SSL rand_bytes function, and then used SSL_write to write the buffer to the ssl stream from client.
2. Server received the number from the stream and stored it into a buffer using SSL_read
3. Server generated the SHA1 hash of the challenge
4. Server encrypted the hash using the private key, and then sent the signature to server using SSL_write
5. Client received the signature from server, and then decryped it using the rsa public key. The decrypted value returns the hash.
6. Client sent the filename passed in from the terminal command line to the server
7. Server receives filename, and check if it exists. If it doesn't exist, it creates the file, and write that it does not exist as the contents of the file.
8. Server sends 1 byte at a time from buffer through SSL_write.
9. Client receives 1 byte at a time, and writes it to an output file. While receiving each byte, it outputs it to the console.
10. Once, finished Client and server does SSL_Shutdown and resets the BIO for infile, so that the pointed is at the start of the read infile.
