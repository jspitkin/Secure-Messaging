# Programming Assignment 3: Secure Messaging
# Written for CS 4480 Computer Networks with Prof. Kobus Van der Merwe
# Last edit: April 24th, 2016
# Author: Jake Pitkin 

import socket
import select
import sys
import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3
from Crypto.Hash import SHA
from Crypto import Random
randomNumber = Random.new().read

# Program entry point
def main(argv):
	# Read in command line arguments
	port, verbose = readArgs(argv)

	# Read in Bob's public key, Bob's private key and private certificate key
	bobPublicKey, bobPrivateKey, signPrivateKey, alicePublicKey = readKeys(verbose)

	# Sign Bob's public key digest.
	bobPublicKeyDigest = SHA.new(open('bobpublic.pem', 'r').read()).digest()
	signature = signPrivateKey.sign(bobPublicKeyDigest, '')[0]

	if verbose:
		print ""
		print "----------------------------------------"
		print "Signing Bob's public key with private certificate key . . ."
		print "----------------------------------------"
		print "The digest of Bob's public key is: " + str(bobPublicKeyDigest)
		print "The signature of the digest is: " + str(hex(signature))

	if verbose:
		print ""
		print "----------------------------------------"
		print "Waiting for Alice to request Bob's public key . . ."
		print "----------------------------------------"

	# Listen for Alice to request Bob's public key
	bobSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	bobSocket.bind(('localhost', int(port)))
	bobSocket.listen(1)
	connectionSocket, addr = bobSocket.accept()
	incomingMessage = connectionSocket.recv(4096)

	
	if incomingMessage == 'publickey':
		# Send Alice the signed digest and Bob's public key
		connectionSocket.send(bobPublicKeyDigest)
		connectionSocket.send(binascii.unhexlify("%x" % signature))
		connectionSocket.send(bobPublicKey.exportKey())

		if verbose:
			print ""
			print "----------------------------------------"
			print "Receiving the signed digest and Bob's public key . . ."
			print "----------------------------------------"

		# Receive the message package from Alice
		messageDigest, signature, encryptedSymmetricKey, encryptedMessage = getEncryptedPackage(bobSocket)

		if verbose:
			print ""
			print "----------------------------------------"
			print "Receiving encrypted message package from Alice . . ."
			print "----------------------------------------"
			print "Got Alice's message digest: " + str(messageDigest)
			print "Got Alice's signature: " + str(hex(long(binascii.hexlify(signature), 16)))
			print "Got Alice's encrypted symmetric key: " + str(hex(long(binascii.hexlify(encryptedSymmetricKey), 16)))
			print "Got Alice's encrypted Message: " + str(hex(long(binascii.hexlify(encryptedMessage), 16)))

		# Decrypt the symmetric key using Bob's private key
		symmetricKeyString = bobPrivateKey.decrypt(encryptedSymmetricKey)
		symmetricKey = DES3.new(symmetricKeyString)

		if verbose:
			print ""
			print "----------------------------------------"
			print "Decrypting the symmetric key using Bob's private key . . ."
			print "----------------------------------------"
			print "The symmetric 3DES key is: " + str(hex(long(binascii.hexlify(symmetricKeyString), 16)))

		# Verify that the message came from Alice
		messageDigestLong = long(binascii.hexlify(messageDigest), 16)
		signatureLong = long(binascii.hexlify(signature), 16)
		messageCameFromAlice = alicePublicKey.verify(messageDigestLong, (signatureLong, None))

		# Decrypt the original message using the symmetric key
		message = symmetricKey.decrypt(encryptedMessage)

		if verbose:
			print ""
			print "----------------------------------------"
			print "Decrypting the message to Alice using the symmetric key . . ."
			print "----------------------------------------"
			print ""

		print "Alice says: " + message.strip()
		print ""

# Reads in relevant public and private RSA keys from file
def readKeys(verbose):
	if verbose:
		print ""
		print "----------------------------------------"
		print "Reading RSA keys from file . . ."
		print "----------------------------------------"
		print "Reading in Bob's public key."
		print "Reading in Bob's private key."
		print "Reading in Alice's public key."
		print "Reading in Certificate private key."

	bobPublicFile = open('bobpublic.pem', 'r')
	bobPublicKey = RSA.importKey(bobPublicFile.read())
	
	bobPrivateFile = open('bobprivate.pem', 'r')
	bobPrivateKey = RSA.importKey(bobPrivateFile.read())

	signPrivateFile = open('signprivate.pem', 'r')
	signPrivateKey = RSA.importKey(signPrivateFile.read())

	alicePublicFile = open('alicepublic.pem', 'r')
	alicePublicKey = RSA.importKey(alicePublicFile)

	return bobPublicKey, bobPrivateKey, signPrivateKey, alicePublicKey

# Reads in the command line args
def readArgs(argv):
	port = ''
	verbose = False

	argCount = len(argv)

	if argCount == 1 and argv[0] != "-v":
		return argv[0], False
	elif argCount == 2 and argv[0] == "-v":
		return argv[1], True
	else:
		print "usage: python bob.py -v (optional) <Port>"
		sys.exit(2)

# Listens for the encrypted message for Alice
def getEncryptedPackage(socket):
	socket.listen(1)
	connectionSocket, addr = socket.accept()
	messageDigest = connectionSocket.recv(4096)

	socket.listen(1)
	connectionSocket, addr = socket.accept()
	signature = connectionSocket.recv(4096)

	socket.listen(1)
	connectionSocket, addr = socket.accept()
	encryptedSymmetricKey = connectionSocket.recv(4096)

	socket.listen(1)
	connectionSocket, addr = socket.accept()
	encryptedMessage = connectionSocket.recv(4096)

	return messageDigest, signature, encryptedSymmetricKey, encryptedMessage

if __name__ == "__main__":
    main(sys.argv[1:])