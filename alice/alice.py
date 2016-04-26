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
	ip, port, verbose = readArgs(argv)

	# As the user for a message to send to Bob
	message = raw_input('Enter a message to send to Bob: ')

	# Pad the message so it's size is a multiple of 8 bytes for 3DES
	if len(message) % 8 != 0:
		message += ' ' * (8 - len(message) % 8)

	# Read in Alice's public key, Alice's private key and public certificate key
	alicePublicKey, alicePrivateKey, signPublicKey = readKeys(verbose)

	# Request Bob's verified public key
	aliceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	aliceSocket.connect((ip, int(port)))
	aliceSocket.send('publickey')

	if verbose:
		print ""
		print "----------------------------------------"
		print "Requesting Bob's verified public key . . ."
		print "----------------------------------------"

	# Receive Bob's public key and a signed digest of his key
	bobPublicKeyDigest = aliceSocket.recv(4096)
	signature = aliceSocket.recv(4096)	
	bobPublicKeyString = aliceSocket.recv(4096)

	# Verify that Bob's public key is authentic
	bobPublicKeyDigestLong = long(binascii.hexlify(bobPublicKeyDigest), 16)
	signatureLong = long(binascii.hexlify(signature), 16)
	bobPublicKeyIsValid = signPublicKey.verify(bobPublicKeyDigestLong, (signatureLong, None))

	if verbose:
		print "Got Bob's key digest: " + str(hex(bobPublicKeyDigestLong))
		print "Got Bob's SHA-1 signature: " + str(hex(signatureLong))
		print "Got Bob's public key: " + bobPublicKeyString
		print ""
		print "----------------------------------------"
		print "Verifying Bob's public key . . ."
		print "----------------------------------------"

	if not bobPublicKeyIsValid:
		print "The public key from Bob isn't valid!"
		print "Exiting . . ."
		sys.exit(2)
	elif verbose:
		print "Bob's public key is valid!"

	# Hash the message with Alice's private key
	messageDigest = SHA.new(message).digest()
	signature = alicePrivateKey.sign(messageDigest, '')[0]

	if verbose:
		print ""
		print "----------------------------------------"
		print "Hashing the message with Alice's private key . . ."
		print "----------------------------------------"
		print "The message is: " + message
		print "The message digest is: " + str(messageDigest)
		print "The message SHA-1 signature is:" + str(hex(signature))

	# Create a symmetric key
	symmetricKeyString = Random.get_random_bytes(24)
	symmetricKey = DES3.new(symmetricKeyString)

	if verbose:
		print ''
		print "----------------------------------------"
		print "Creating a symmetric key . . ."
		print "----------------------------------------"
		print "The symmetric key is: " + str(hex(long(binascii.hexlify(symmetricKeyString), 16)))
	
	# Encrypt the symmetric key with Bob's public key
	bobPublicKey = RSA.importKey(bobPublicKeyString)
	encryptedSymmetricKey = bobPublicKey.encrypt(symmetricKeyString, 31)

	if verbose:
		print ""
		print "----------------------------------------"
		print "Encrypting the symmetric key with Bob's public key . . ."
		print "----------------------------------------"
		print "The encrypted key is: " + str(hex(long(binascii.hexlify(encryptedSymmetricKey[0]), 16)))

	# Encrypt the message with the symmetric key
	encryptedMessage = symmetricKey.encrypt(message)

	if verbose:
		print ""
		print "----------------------------------------"
		print "Encryping the message with the summetric key . . . "
		print "----------------------------------------"
		print "The encrypted message is: " + str(hex(long(binascii.hexlify(encryptedMessage), 16)))

	# Send the message package to Bob
	sendEncryptedPackage(ip, port, messageDigest, signature, encryptedSymmetricKey, encryptedMessage)

	if verbose:
		print ""
		print "----------------------------------------"
		print "Sending encrypted message package to Bob. . ."
		print "----------------------------------------"
		print "Sent successfully!"
	

# Reads in relevant public and private RSA keys from file
def readKeys(verbose):
	if verbose:
		print ""
		print "----------------------------------------"
		print "Reading RSA keys from file . . ."
		print "----------------------------------------"
		print "Reading in Alice's public key."
		print "Reading in Alice's private key."
		print "Reading in Certificate public key."

	alicePublicFile = open('alicepublic.pem', 'r')
	alicePublicKey = RSA.importKey(alicePublicFile.read())
	
	alicePrivateFile = open('aliceprivate.pem', 'r')
	alicePrivateKey = RSA.importKey(alicePrivateFile.read())

	signPublicFile = open('signpublic.pem', 'r')
	signPublicKey = RSA.importKey(signPublicFile.read())

	return alicePublicKey, alicePrivateKey, signPublicKey	

# Reads in the command line args
def readArgs(argv):
	ip = ''
	port = ''
	verbose = False

	argCount = len(argv)

	if argCount == 2 and argv[0] != "-v":
		return argv[0], argv[1], False
	elif argCount == 3 and argv[0] == "-v":
		return argv[1], argv[2], True
	else:
		print "usage: python alice.py -v (optional) <IP address> <Port>"
		sys.exit(2)

# Sends an encrypted package to Bob
def sendEncryptedPackage(ip, port, messageDigest, signature, encryptedSymmetricKey, encryptedMessage):
	aliceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	aliceSocket.connect((ip, int(port)))
	aliceSocket.send(messageDigest)
	aliceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	aliceSocket.connect((ip, int(port)))
	aliceSocket.send(binascii.unhexlify("%x" % signature))
	aliceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	aliceSocket.connect((ip, int(port)))
	aliceSocket.send(encryptedSymmetricKey[0])
	aliceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	aliceSocket.connect((ip, int(port)))
	aliceSocket.send(encryptedMessage)

if __name__ == "__main__":
	main(sys.argv[1:])