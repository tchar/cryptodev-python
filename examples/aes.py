"""
This is a simple example on how to use the cryptodev module (aes) with python.

A relevant example in C language can be found here:
https://github.com/cryptodev-linux/cryptodev-linux/blob/master/examples/aes.c
This example is a copy of the above example without using session_info_op
and thus, without using alignmask. It can be changed though to use it.

This module is compatible with python 2.7 version and above (including python 3 version).

You can remove all methods that are defined below the Crypto class and use this code as
a standalone python module to encrypt and decrypt data.

Author Tilemachos Charalampous <tilemachos.charalampous@gmail.com>
"""

from __future__ import print_function
import sys
# You can remove this if your cryptodev module is in the same folder
sys.path.append('../crypto')
from cryptodev import *
from ctypes import c_uint8, create_string_buffer, cast, byref, POINTER, CDLL
import fcntl
import os
import traceback
import logging
import binascii

libc = CDLL('libc.so.6')
BLOCK_SIZE 	= 16
KEY_SIZE 	= 16

"""
Below are some custom Exceptions defined
that are used in the Crypto class
"""
class InputException(Exception):
	pass

class EncryptException(Exception):
	pass

class DecryptException(Exception):
	pass

class SessionException(Exception):
	pass

class OpenCryptoException(Exception):
	pass


def new(key, iv):
	"""
	Call this to get a copy of a Crypto object
	"""
	return Crypto(key, iv)

class Crypto:
	"""
	This is the Crypto class. It is used to encrypt and decrypt data.
	Get a copy of this class using the new method and passing a key and an iv
	of length multiple of 16. You can encrypt and decrypt data using the
	encrypt() and decrypt() methods.
	Methods to be used externally are: encrypt(), decrypt(), close().
	All other methods are used internally by this class.
	"""

	class Data:
		"""
		This is the Data class.
		Holds information about key, iv, input data,
		encrypted data and decrypted data.
		"""
		def __init__(self, key, iv, keysize, blocksize):
			self.key = create_string_buffer(key, keysize)
			self.iv = create_string_buffer(iv, blocksize)
			self.encrypted = None
			self.decrypted = None
			self.inpt = None

	def __init__(self, key, iv):
		"""
		Init crypto.
		Checks key length and iv length to be a power of 2
		Init data.
		Open crypto device
		"""
		if not len(key) or len(key) & (len(key) - 1):
		   raise InputException('Key must have length power of 2')
		if not len(iv) or len(iv) & (len(iv) - 1):
		   raise InputException('Key must have length power of 2')
		self.sess = session_op()
		self.cryp = crypt_op()
		# Define buffer size, key size and block size
		self.keysize = len(key)
		self.blocksize= len(iv)
		self.data = self.Data(key, iv, self.keysize, self.blocksize)
		self.__crypto_open()

	def __init_sess(self):
		"""
		Method to initialize the session.
		"""
		self.sess.cipher = CRYPTO_AES_CBC
		self.sess.keylen = self.keysize
		self.sess.key = cast(self.data.key, POINTER(c_uint8))
		if libc.ioctl(self.fd, CIOCGSESSION, byref(self.sess)):
			raise SessionException('CIOCGSESSION error')
		self.cryp.ses = self.sess.ses
		self.cryp.iv = cast(self.data.iv, POINTER(c_uint8))

	def __deinit_sess(self):
		"""
		Method to finish the session.
		"""
		if libc.ioctl(self.fd, CIOCFSESSION, byref(self.sess, session_op.ses.offset)):
			raise SessionException('CIOCFSESSION error')

	def encrypt(self, data):
		"""
		Method to encrypt the data.
		Sets the input and initializes the session.
		Encrypts, sets the encrypted data and finishes the session.
		"""
		self.__set_input(data)
		self.__init_sess()
		self.cryp.len = sizeof(self.data.inpt)
		self.cryp.src = cast(self.data.inpt, POINTER(c_uint8))
		self.cryp.dst = cast(self.data.encrypted, POINTER(c_uint8))
		self.cryp.op = COP_ENCRYPT
		if libc.ioctl(self.fd, CIOCCRYPT, byref(self.cryp)):
			raise EncryptException('CIOCRYPT error')
		self.__deinit_sess()
		return self.__get_encrypted()

	def decrypt(self, data):
		"""
		Method to decrypt the data.
		Sets the encrypted data and initializes the session.
		Decrypts, sets the decrypted data and finishes the session.
		"""
		self.__set_encrypted(data)
		self.__init_sess()
		self.cryp.len = sizeof(self.data.encrypted)
		self.cryp.src = cast(self.data.encrypted, POINTER(c_uint8))
		self.cryp.dst = cast(self.data.decrypted, POINTER(c_uint8))
		self.cryp.op = COP_DECRYPT
		if libc.ioctl(self.fd, CIOCCRYPT, byref(self.cryp)):
			raise DecryptException('CIOCCRYPT error')
		self.__deinit_sess()
		return self.__get_decrypted()

	def __get_encrypted(self):
		"""
		Getter for the encrypted data, not to be used externally.
		"""
		return self.data.encrypted.raw

	def __get_decrypted(self):
		"""
		Getter for the decrypted data, not to be used externally.
		"""
		return self.data.decrypted.raw

	def __set_encrypted(self, encbuf):
		"""
		Setter for the encrypted data, not to be used externally.
		Raises an InputException if the length is not multiple of size 16.
		This is because we are using CRYPTO_AES_CBC mode.
		If we didn't raise an Exception here we would get CIOCCRYPT error.
		"""
		if len(encbuf) % 16 != 0:
			raise InputException('Input must be a multiple of size 16, it is ' + str(len(encbuf)))
		self.data.encrypted = create_string_buffer(encbuf, len(encbuf))
		self.data.decrypted = create_string_buffer(b'', len(encbuf))

	def __set_input(self, inpt):
		"""
		Setter for the input data, not to be used externally.
		Raises an InputException if the length is not multiple of size 16.
		This is because we are using CRYPTO_AES_CBC mode.
		If we didn't raise an Exception here we would get CIOCCRYPT error.
		"""
		if len(inpt) % 16 != 0:
			raise InputException('Input must be a multiple of size 16, it is ' + str(len(inpt)))
		self.data.inpt = create_string_buffer(inpt, len(inpt))
		self.data.encrypted = create_string_buffer(b'', len(inpt))

	def __crypto_open(self):
		"""
		Method used to open the crypto device. Not to be used externally
		Raises OpenCryptoException if device cannot be opened.
		"""
		try:
			self.fd = os.open("/dev/crypto", os.O_RDWR)
		except OSError as e:
			raise OpenCryptoException(str(e))

	def close(self):
		"""
		Method to used to close the crypto device.
		"""
		self.__crypto_close()

	def __crypto_close(self):
		"""
		Called by close() method to close the crypto device.
		Not to be used externally.
		"""
		try:
			os.close(self.fd)
		except OSError as e:
			raise OpenCryptoException(str(e))


def str2hex(s):
	"""
	Method to convert a string to hex string.
	"""
	#use decode for python 3 compatibility
	return binascii.hexlify(s).decode('utf-8')

def test_encrypt(crypto, data):
	"""
	Test encryption and return encrypted data.
	"""
	return crypto.encrypt(data)

def test_decrypt(crypto, data):
	"""
	Test decryption and return decrypted data.
	"""
	return crypto.decrypt(data)

def test():
	"""
	Test Crypto.
	"""
	try:
		# Create a random key, iv and data.
		key = os.urandom(KEY_SIZE)
		iv = os.urandom(BLOCK_SIZE)
		data = os.urandom(BLOCK_SIZE)
		# Get a new instance of Crypto
		crypto = new(key, iv)
		# Get the encrypted data
		encrypted_data = test_encrypt(crypto, data)
		# Get the decrypted data
		decrypted_data = test_decrypt(crypto, encrypted_data)
		# Print results
		print('Original data : ' + str2hex(data))
		print('Encrypted data : ' + str2hex(encrypted_data))
		print('Decrypted data : ' + str2hex(decrypted_data))
		# Check if test passes
		if data == decrypted_data:
			print('Test passed')
		else:
			print('Test failed')
		# Close the crypto device
		crypto.close()
	except (SessionException, EncryptException,
		   DecryptException, OpenCryptoException,
		   InputException) as e:
		logging.exception(str(e))

if __name__ == '__main__':
	test()
