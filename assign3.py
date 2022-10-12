# import from pycryptodome
from codecs import utf_16_be_decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import os
from Crypto.Util import number

# -- Bob Functions --
def bobPublicKey(p, g):
    #print("Bob Public Key")

     # generate random number between 1 and (p-1)
    b = random.randint(1, (p -1))

    # - g raised to the power of a 
    # - (g^a) mod p
    B = pow(g, b,  p)

    # return bob public key and random int b
    return B, b

def bobPrivateKey(A, b, p):
    #print("Bob Private Key")

    # - A raised to the power of b
    # - (A^b) mod p
    s = pow(A, b, p)

    # return bob private key
    return s

def bobEncryptMessage(key, iv):

    bobMessage = b"Hi Alice!"

    # use CBC mode of encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # encrypt message using Bob's private key
    encrypted_message = cipher.encrypt(pad(bobMessage, AES.block_size))

    return encrypted_message

def decryptAlice(aCipherText, key, iv):

    # use CBC mode of decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)

     # decrypt the cipher text from alice using Bob's private key
    decrypted_message = cipher.decrypt(aCipherText)

    unpaddm = unpad(decrypted_message, AES.block_size)
    unpaddm = str(unpaddm, "utf-8")
    print(unpaddm)

# -----------------------

# -- Alice Functions -- 

def alicePublicKey(p, g):
    #print("Alice Public Key")

    # generate random number between 1 and (p-1)
    a = random.randint(1, (p -1))

    # - g raised to the power of a 
    # - (g^a) mod p
    A = pow(g, a,  p)

    # return alice public key and random number a 
    return A, a

def alicePrivateKey(B, a, p):
    #print("Alice Private Key")

    # - B raised to the power of a
    # - (B^a) mod p
    s = pow(B, a, p)

    # return private key
    return s

def aliceEncryptMessage(key, iv):
    
    # alice message
    aliceMessage = b"Hi Bob!"

    # 
    paddedMessage = pad(aliceMessage, AES.block_size)

    # use CBC mode of encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # encrypt message using Alice's private key
    encrypted_message = cipher.encrypt(paddedMessage)

    return encrypted_message

def decryptBob(bCipherText, key, iv):

    # generate a CBC mode of decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # decrypt the cipher text from bob using Alice's private key
    decrypted_message = cipher.decrypt(bCipherText)

    unpaddm = unpad(decrypted_message, AES.block_size)
    unpaddm = str(unpaddm, "utf-8")
    print(unpaddm)

# -----------------------

# -- Mallory Functions --

def malloryTampers(A, B):

    # mallory tampered with Alice's and Bob's public key values
    tamperedA = A - 33
    tamperedB = B - 11

    return tamperedA, tamperedB

def malloryRecoversMessage(bCipherText, newAliceByteArray, aCipherText, newBobByteArray, iv):
    
    # generate a CBC mode of decryption
    cipher = AES.new(newAliceByteArray, AES.MODE_CBC, iv)

    # decrypt the cipher text from bob using Alice's private key
    bob_decrypted_message = cipher.decrypt(bCipherText)

    # generate a CBC mode of decryption
    cipher = AES.new(newBobByteArray, AES.MODE_CBC, iv)

    # decrypt the cipher text from alice using Bob's private key
    alice_decrypted_message = cipher.decrypt(aCipherText)

    print("Mallory decrypted both Alice's and Bob's messages to each other.")

    aunpaddm = unpad(alice_decrypted_message, AES.block_size)
    aunpaddm = str(aunpaddm, "utf-8")
    print("Alice's message to Bob: ", aunpaddm)

    bunpaddm = unpad(bob_decrypted_message, AES.block_size)
    bunpaddm = str(bunpaddm, "utf-8")
    print("Bob's message to Alice: ", bunpaddm)

def diffieHellman(p, g):

    #print("in diffie hellman")

    # return Alice public key (A) and random nummber generated (a)
    A, a = alicePublicKey(p,g)

    # return Bob public key (B) and random nummber generated (b)
    B, b = bobPublicKey(p, g)

    # create alice private key
    apk = alicePrivateKey(B, a, p)

    # create bob private key
    bpk = bobPrivateKey(A, b, p)

    # convert alice private key into bytes
    #apkByte = bytes(apk)
    apk = str(apk)
    apkByte = apk.encode()

    # convert bob private key into bytes
    #bpkByte = bytes(bpk)
    bpk = str(bpk)
    bpkByte = bpk.encode()

    # create SHA-256 hash function
    h1 = SHA256.new()
    h2 = SHA256.new()

    # pass alice private key to SHA-256 hash function
    h1.update(apkByte)

    # pass bob private key to SHA-256 hash function
    h2.update(bpkByte)

    # create alice and bob byte arrays
    aliceByteArray = bytearray(h1.hexdigest(), 'utf-8')
    bobByteArray = bytearray(h2.hexdigest(), 'utf-8')

    # truncate 16 bytes alice and bob keys
    newAliceByteArray = aliceByteArray[:16]
    newBobByteArray = bobByteArray[:16]

    # generate iv
    iv = os.urandom(16)

    # pass keys in and iv to encrypt messages
    aliceCipherText = aliceEncryptMessage(newAliceByteArray, iv)
    bobCipherText = bobEncryptMessage(newBobByteArray, iv)

    print("Diffie-Hellman Key Exchange: ")

    print("Alice's private key decrypts Bob's cipher text.")
    # use alice's private key to decrypt bob's cipher text
    decryptBob(bobCipherText, newAliceByteArray, iv)

    print("Bob's private key decrypts Alice's cipher text.")
    # use bob's private key to decrypt alice's cipher text
    decryptAlice(aliceCipherText, newBobByteArray, iv)

def MITM(p, g):

    #print("in mitm")

     # return Alice public key (A) and random nummber generated (a)
    A, a = alicePublicKey(p,g)

    # return Bob public key (B) and random nummber generated (b)
    B, b = bobPublicKey(p, g)

    # mallory tampers with public key of Alice and Bob
    tamperedA, tamperedB = malloryTampers(A, B)

    # create alice private key
    apk = alicePrivateKey(tamperedB, a, p)

    # create bob private key
    bpk = bobPrivateKey(tamperedA, b, p)

    # convert alice private key into bytes
    apk = str(apk)
    apkByte = apk.encode()

    # convert bob private key into bytes
    bpk = str(bpk)
    bpkByte = bpk.encode()

    # create SHA-256 hash function
    h1 = SHA256.new()
    h2 = SHA256.new()

    # pass alice private key to SHA-256 hash function
    h1.update(apkByte)

    # pass bob private key to SHA-256 hash function
    h2.update(bpkByte)

    # create alice and bob byte arrays
    aliceByteArray = bytearray(h1.hexdigest(), 'utf-8')
    bobByteArray = bytearray(h2.hexdigest(), 'utf-8')

    # truncate 16 bytes alice and bob keys
    newAliceByteArray = aliceByteArray[:16]
    newBobByteArray = bobByteArray[:16]

    # print and show that mallory tampered with Alice's and Bob's keys (not the same)
    print("Alice's Private Key: ", str(newAliceByteArray, "utf-8"))
    print("Bob's Private Key: ", str(newBobByteArray, "utf-8"))
    print("Alice's and Bob's private keys are different because Alice " 
    "tampered with the numbers in the protocol.")

def MITM2(p, g):

    # mallory tampers with generator g
    g = 1

    # return Alice public key (A) and random nummber generated (a)
    A, a = alicePublicKey(p,g)

    # return Bob public key (B) and random nummber generated (b)
    B, b = bobPublicKey(p, g)

    # create alice private key
    apk = alicePrivateKey(B, a, p)

    # create bob private key
    bpk = bobPrivateKey(A, b, p)

    # convert alice private key into bytes
    apk = str(apk)
    apkByte = apk.encode()

    # convert bob private key into bytes
    bpk = str(bpk)
    bpkByte = bpk.encode()

    # create SHA-256 hash function
    h1 = SHA256.new()
    h2 = SHA256.new()

    # pass alice private key to SHA-256 hash function
    h1.update(apkByte)

    # pass bob private key to SHA-256 hash function
    h2.update(bpkByte)

    # create alice and bob byte arrays
    aliceByteArray = bytearray(h1.hexdigest(), 'utf-8')
    bobByteArray = bytearray(h2.hexdigest(), 'utf-8')

    # truncate 16 bytes alice and bob keys
    newAliceByteArray = aliceByteArray[:16]
    newBobByteArray = bobByteArray[:16]

    # generate iv
    iv = os.urandom(16)

    # pass keys in and iv to encrypt messages
    aliceCipherText = aliceEncryptMessage(newAliceByteArray, iv)
    bobCipherText = bobEncryptMessage(newBobByteArray, iv)

    # Mallory is able to recover both Alice's and Bob's encrypted messages
    malloryRecoversMessage(bobCipherText, newAliceByteArray, aliceCipherText, newBobByteArray, iv)

def textbookRSA(e, p, q):

    #print("rsa")

    # calculate p x q = n
    n = p * q

    # get (p-1)(q-1)
    subp = p - 1
    subq = q - 1

    # calculate oN = (p-1)(q-1)
    oN = subp * subq

    # calculate d 
    d = pow(e, -1, oN)

    # make sure d was calculated correctly
    num = pow(d * e, 1, oN)
    #print(num)

    # create public key
    publicKey = [e, n]
    # create private key
    privateKey = [d, n]

    # bob picks random elemet in n 
    bobNum = 45

    # generate y
    y = pow(bobNum, e, n)

    # alice 
    x = pow(y, e, n)

    # create plaintext
    plaintext = "Get a buckskin"

    # encode plaintext
    s = plaintext.encode('utf-8')

    # convert ascii string to hex
    hexValue = s.hex()

    # convert hex into integer value
    intValue = int(hexValue, 16)

    print("Plaintext Number Before Encryption: ", intValue)

    # create cipher text, C = M^e mod n
    ciphertext = pow(intValue, e, n)

    # decrypt cipher text, M = C^d mod n
    plaintext_decrypt = pow(ciphertext,d, n)

    print("Plaintext Number After Decryption: ", plaintext_decrypt)

def malleableBob(n, e):

    # Bob's random number s < n
    s = 45
    
    # create cipher text, s^e mod n 
    c = pow(s, e, n)

    # return the cipher text
    return c

def malleableMallory(c):

    # cPrime equals to 1, 
    cPrime = 1

    # return cPrime
    return cPrime

def malleableAlice(cPrime, d, n, iv):

    # create cipher text, c'^d mod n
    s = pow(cPrime, d, n)

    # create SHA256 hash function
    h = SHA256.new()

    # convert alice private key into bytes
    s = str(s)
    sByte = s.encode()
    
    # pass s into SHA256
    h.update(sByte)

    # generate key
    key = h.digest()

    #print(key)

    # alice message
    aliceMessage = b"Hi Bob!"

    # pad alice's message
    paddedMessage = pad(aliceMessage, AES.block_size)

    # use CBC mode of encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # encrypt message using Alice's private key
    encrypted_message = cipher.encrypt(paddedMessage)

    return encrypted_message, key

def malloryDecrypts(aEncryptedMessage, iv, key):

    # generate a CBC mode of decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # decrypt the cipher text from bob using Alice's private key
    decrypted_message = cipher.decrypt(aEncryptedMessage)

    print("Mallory intercepted the messagee from Alice going to Bob:")
    unpaddm = unpad(decrypted_message, AES.block_size)
    unpaddm = str(unpaddm, "utf-8")
    print(unpaddm)

def malleableRSA(e, p, q):
    #print("malleable")

    # calculate p x q = n
    n = p * q

    # get (p-1)(q-1)
    subp = p - 1
    subq = q - 1

    # calculate oN = (p-1)(q-1)
    oN = subp * subq

    # calculate d 
    d = pow(e, -1, oN)

    # make sure d was calculated correctly
    num = pow(d * e, 1, oN)
    #print(num)

    # create public key
    publicKey = [e, n]
    # create private key
    privateKey = [d, n]

    # generate iv
    iv = os.urandom(16)

    c = malleableBob(n, e)

    cPrime = malleableMallory(c)

    alice_encrypted_message, key= malleableAlice(cPrime , d, n, iv)

    #print(alice_encrypted_message)

    # since mallory changed c to 1 the key will alawys be 1 
    # she can generate her own key that matches the secret key of alice and bob
    malloryDecrypts(alice_encrypted_message, iv, key)

def main():

    #print("this is main")

    # 1024 bit parameters
    p = 37
    g = 5

    p1024 = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
    newp = int(p1024, 16)

    g1024 = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"
    newg = int(g1024, 16)
    
    # Task 1 
    # - Diffie-Hellman Key Exchange
    #diffieHellman(p, g)
    diffieHellman(newp, newg)
    
    # Task 2
    # - implement man-in-the-middle attacks

    # tamper with public keys of Alice and Bob
    MITM(newp, newg)

    #print("")
    # tamper with g value
    MITM2(newp, newg)


    # pick random e value 
    task3e = 65537

    # length of prime numbers
    n_length = 2048

    # generate two 2048 bit prime numbers
    primeNum1 = number.getPrime(n_length)
    primeNum2 = number.getPrime(n_length)

    # Task 3
    textbookRSA(task3e, primeNum1, primeNum2)

    # malleable RSA
    # - mallory is permitted to change c or substitute c and send c'(changed c) to alice
    # - mallory wants to read 'hi bob'
    # - make a F() to generate c', exponentiation property
    malleableRSA(task3e, primeNum1, primeNum2)


main()
