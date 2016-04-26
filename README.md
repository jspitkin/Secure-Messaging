****************
* Introduction

This secure messanger is written in Python 2.7.5 with the assistance of the PyCrypto library. Using SHA-1, RSA keys, and 3DES a message is securely sent from Alice to Bob. Death to all rats and snitches.

********************
*  Included Files 

alice.tar.gz - includes alice.py (message sender), Alice's public key, Alice's private key and the certificate public key.

bob.tar.gz - includes bob.py (message receiver), Alice's public key, Bob's public key, Bob's private key, certificate public key and certificate private key.

pycrypto-2.6.1 - the PyCrypto library used for the cryptography functions of my secure messaging system.

makeKeys.py - Python script to generate the RSA public and private keys beforehand.

readme.txt - Readme file

**************
* How To Use

1) Extract bob.tar.gz one one CADE machine and alice.tar.gz on another CADE machine. Both machines also need the pycrypto-2.6.1 library.

2) First run the bob.py script using: "python bob.py -v <port>". The -v flag is optional and will toggle verbose mode. The port is the port Bob will be listening on, waiting for Alice to request Bob's public key. bob.py will now wait for alice.py to communicate.

3) Now run alice.py on another machine using "python alice.py -v <IP address> <Port>". The -v flag is optional and will toggle verbose mode. The IP address and port are the IP address and port of the machine bob.py is running on.

4) The alice.py script will request a message from you at the command line. Type in a message and the process will begin. You should see the message arrive on the machine running bob.py. The verbose mode will have a detailed breakdown of each step of the process.


