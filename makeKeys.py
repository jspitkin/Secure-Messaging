from Crypto.PublicKey import RSA
from Crypto import Random
randomNumber = Random.new().read

# Bob's public and private keys
key = RSA.generate(1024, randomNumber)
f = open('bobpublic.pem', 'w')
f.write(key.publickey().exportKey())
f.close()
f = open('bobprivate.pem', 'w')
f.write(key.exportKey())
f.close()

# Alice's public and private keys
key = RSA.generate(1024, randomNumber)
f = open('alicepublic.pem', 'w')
f.write(key.publickey().exportKey())
f.close()
f = open('aliceprivate.pem', 'w')
f.write(key.exportKey())
f.close()

# Certificate public and private keys
key = RSA.generate(1024, randomNumber)
f = open('signpublic.pem', 'w')
f.write(key.publickey().exportKey())
f.close()
f = open('signprivate.pem', 'w')
f.write(key.exportKey())
f.close()
