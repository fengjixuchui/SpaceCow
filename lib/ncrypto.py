from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import base64, ast

def generate_keys():
	# RSA modulus length must be a multiple of 256 and >= 1024
	modulus_length = 256*4 # use larger value in production
	privatekey = RSA.generate(modulus_length, Random.new().read)
	publickey = privatekey.publickey()
	return privatekey, publickey

def encrypt_message(a_message , publickey):
	try:
		encryptor = PKCS1_OAEP.new(publickey)
		encrypted_msg = encryptor.encrypt(a_message)
		encoded_encrypted_msg = base64.b64encode(encrypted_msg) # base64 encoded strings are database friendly
		return encoded_encrypted_msg
	except Exception as e:
		print("nCRYPTO: %s"%str(e))

def decrypt_message(encoded_encrypted_msg, privatekey):
	decryptor = PKCS1_OAEP.new(privatekey)
	decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
	decoded_decrypted_msg = decryptor.decrypt(ast.literal_eval(str(decoded_encrypted_msg)))
	return decoded_decrypted_msg