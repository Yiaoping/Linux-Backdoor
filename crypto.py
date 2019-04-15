import base64
import math
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from binascii import hexlify, unhexlify
from Crypto.Cipher import PKCS1_OAEP as Cipher_PKCS1_v1_5

def RSAEncrypt(msgKey):
    public_key_string = open("public.pem", "rb").read()
    print(public_key_string)
    publickey = RSA.importKey(public_key_string)
    cipherKey = Cipher_PKCS1_v1_5.new(publickey)

    msgKey = msgKey.encode("utf8")
    encryptedMsg = cipherKey.encrypt(msgKey)
    print(encryptedMsg)
    #returns a tuple of ciphertext and "none"
    message = encryptedMsg +  "~".encode("utf8")
    return message 


def RSADecrypt(msgKey):
    private_key_string = open("priv.der", "rb").read()
    private_key = RSA.importKey(private_key_string)
    decryptor = Cipher_PKCS1_v1_5.new(private_key)
    decryptedMsg = decryptor.decrypt(msgKey)

    return decryptedMsg.decode("utf8")

def aesEncrypt(msg):
    key = "passwordpassword".encode("utf8")
    iv = "This is an IV456".encode("utf8")
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(msg)

    return iv + ciphertext




def aesDecrypt(ciphertext):
    key = "passwordpassword".encode("utf8")
    iv = ciphertext[:16]

    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    msg = cipher.decrypt(ciphertext)

    return msg.decode("utf-8")

def aesDecryptFileSending(ciphertext):
    key = "passwordpassword".encode("utf8")
    iv = "This is an IV456".encode("utf8")

    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    msg = cipher.decrypt(ciphertext)

    return msg 

#Vigenere cipher
def encryptData(data):
    key = "password"
    bytes_data = data
    encoded_chars = []

    for i in range(len(bytes_data)):
        key_c = key[i%len(key)]
        encoded_c = chr(ord(data[i]) + ord(key_c) % 256)
        encoded_chars.append(encoded_c)
    encoded_string = "".join(encoded_chars)
    print(encoded_string)

    return encoded_string


def decryptData(data):
    key = "password"
    encoded_chars = []

    for i in range(len(data)):
        key_c = key[i%len(key)]
        encoded_c = chr((256 + ord(data[i]) - ord(key_c)) % 256)
        encoded_chars.append(encoded_c)
    encoded_string = "".join(encoded_chars)
    print(encoded_string)

    return encoded_string


#transposition cipher
def encryptData2(key, data):

    key = 8
    ciphertext = [''] * key
    #create a column for each letter of the key
    for col in range(key):
        pointer = col

        while pointer < len(data):
            ciphertext[col] += data[pointer]

            pointer +=key

    
    encryptedString2 =  ''.join(ciphertext)
    bytesEncodedString = bytes(encryptedString2, 'utf8')
    return base64.b64encode(bytesEncodedString)


def decryptData2(key, data):

    data = base64.b64decode(data)
    data = data.decode("utf8")

    numOfColumns = math.ceil(len(data)/key)
    numOfRows = key
    numOfShadedBox = (numOfColumns * numOfRows) - len(data)

    text = [''] * numOfColumns

    col = 0
    row = 0

    for s in data:
        text[col] += s
        col +=1

        if (col == numOfColumns) or (col == numOfColumns-1 and row >= numOfRows - numOfShadedBox):
            col = 0
            row += 1

    return ''.join(text)