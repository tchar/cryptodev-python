'''
This is a Python rip from cipher-aead-srtp.c.
Some useful info following:
We are using libc's ioctl and fcnt instead of fcntl's because sometimes addressof()
returns really big numbers. This causes problems to fcntl's ioctl (for more follow the link below):
http://hg.python.org/cpython/file/bc6d28e726d8/Python/getargs.c#l659
fcntl's ioctl/fcntl won't accent ctypes' byref() (another reason to use libc's ioctl/fcntl).
Brief documentation of byref(), addressof() and POINTER() usage:
    byref():    Used to pass any reference (light pointer() object) to ioctl/fcntl.
                Used when calling libc's ioctl and not fcntl's ioctl
    addressof():Used to get the real address of a ctypes object. This is used only
                when translating specific C code into Python code (C code is similar to the following):
                plaintext = (char *)(((unsigned long)plaintext_raw + siop.alignmask) & ~siop.alignmask);
    POINTER():  Used when casting a ctypes object to a POINTER object (of a ctype object).
                Mostly used when casting to POINTER(c_uint8)

Author: Tilemachos Charalampous <tilemachos.charalampous@gmail.com>
'''

from ctypes import CDLL, byref, addressof, POINTER, sizeof, memset, memmove, c_uint8, c_char_p, c_uint, create_string_buffer, cast, c_byte
from cryptodev import *
from os import open, close, O_RDWR
from fcntl import F_SETFD
from traceback import format_exc


libc = CDLL("libc.so.6")
DATA_SIZE = (8*1024)
HEADER_SIZE = 193
PLAINTEXT_SIZE = 1021
FOOTER_SIZE = 15
BLOCK_SIZE = 16
KEY_SIZE = 16

MAC_SIZE = 20 # SHA1

debug = True

def get_sha1_hmac(cfd, key, key_size, data, data_size, mac):
	try:
		sess = session_op()
		cryp = crypt_op()

		memset(byref(sess), 0, sizeof(sess))
		memset(byref(cryp), 0, sizeof(cryp))

		sess.cipher = 0;
		sess.mac = CRYPTO_SHA1_HMAC
		sess.mackeylen = key_size
		sess.mackey = cast(key, POINTER(c_uint8))
		if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
			#perror("ioctl(CIOCGSESSION)");
			print "ioctl (CIOCGSESSION) error"
			return False


		# Encrypt data.in to data.encrypted
		cryp.ses = sess.ses
		cryp.len = data_size
		cryp.src = cast(data, POINTER(c_uint8))
		cryp.dst = None
		cryp.iv = None
		cryp.mac = cast(mac, POINTER(c_uint8))
		cryp.op = COP_ENCRYPT
		if libc.ioctl(cfd, CIOCCRYPT, byref(cryp)):
			#perror("ioctl(CIOCCRYPT)");
			print "ioctl (CIOCCRYPT) error"
			return False


		# Finish crypto session
		if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
			#perror("ioctl(CIOCFSESSION)");
			print "ioctl (CIOCGSESSION) error"
			return False


		return True
	except Exception, e:
		print str(e)
		print format_exc()
		return False


def print_buf(desc, buf, size):
    print desc + "".join("{:02x}".format(ord(c)) for c in buf.value[:size])


def test_crypto(cfd):
	try:
		plaintext_raw = create_string_buffer(DATA_SIZE + 63)
		plaintext = c_char_p()
		ciphertext_raw = create_string_buffer(DATA_SIZE + 63)
		ciphertext = c_char_p()
		iv = create_string_buffer(BLOCK_SIZE)
		key = create_string_buffer(KEY_SIZE)
		sha1mac = create_string_buffer(20)
		tag = create_string_buffer(20)
		mackey = create_string_buffer("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")
		mackey_len = 16

		sess = session_op()
		co = crypt_op()
		cao = crypt_auth_op()
		siop = session_info_op()

		memset(byref(sess), 0, sizeof(sess))
		memset(byref(cao), 0, sizeof(cao))
		memset(byref(co), 0, sizeof(co))

		memset(byref(key),0x33,  sizeof(key))
		memset(byref(iv), 0x03,  sizeof(iv))

		# Get crypto session for AES128
		sess.cipher = CRYPTO_AES_CTR
		sess.keylen = KEY_SIZE
		sess.key = cast(key, POINTER(c_uint8))

		sess.mac = CRYPTO_SHA1_HMAC
		sess.mackeylen = mackey_len
		sess.mackey = cast(mackey, POINTER(c_uint8))

		if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
			#perror("ioctl(CIOCGSESSION)");
			print "ioctl (CIOCGSESSION) error"
			return False


		siop.ses = sess.ses
		if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)):
			#perror("ioctl(CIOCGSESSINFO)");
			print "ioctl (CIOCGSESSINFO) error"
			return False


		if debug:
			print "requested cipher CRYPTO_AES_CBC/HMAC-SHA1, got %s with driver %s" % (
				siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name)

		plaintext.value = (addressof(plaintext_raw) + siop.alignmask) & ~siop.alignmask
		ciphertext.value = (addressof(ciphertext_raw) + siop.alignmask) & ~siop.alignmask

		memset(plaintext, 0x15, HEADER_SIZE) # header
		memset(c_char_p(addressof(cast(plaintext, POINTER(c_char)).contents)
				+ HEADER_SIZE), 0x17, PLAINTEXT_SIZE) # payload
		memset(c_char_p(addressof(cast(plaintext, POINTER(c_char)).contents)
				+ HEADER_SIZE + PLAINTEXT_SIZE), 0x22, FOOTER_SIZE)

		memmove(ciphertext, plaintext, DATA_SIZE)



		# Encrypt data.in to data.encrypted
		cao.ses = sess.ses
		cao.len = PLAINTEXT_SIZE
		cao.auth_len = HEADER_SIZE+PLAINTEXT_SIZE+FOOTER_SIZE
		cao.auth_src = cast(ciphertext, POINTER(c_uint8))
		tmp = c_char_p(addressof(cast(ciphertext, POINTER(c_char)).contents)
					+ HEADER_SIZE) # this is ciphertext + HEADER_SIZE
		cao.src = cast(tmp, POINTER(c_uint8))
		cao.dst = cao.src
		cao.iv = cast(iv, POINTER(c_uint8))
		cao.op = COP_ENCRYPT
		cao.flags = COP_FLAG_AEAD_SRTP_TYPE
		cao.tag = cast(tag, POINTER(c_uint8))
		cao.tag_len = 20

		if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)):
			#perror("ioctl(CIOCAUTHCRYPT)");
			print "ioctl (CIOCAUTHCRYPT) error"
			return False



		if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
			#perror("ioctl(CIOCFSESSION)");
			print "ioctl (CIOCGSESSION) error"
			return False


		# Get crypto session for AES128
		memset(byref(sess), 0, sizeof(sess))
		sess.cipher = CRYPTO_AES_CTR
		sess.keylen = KEY_SIZE
		sess.key = cast(key, POINTER(c_uint8))

		if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
			#perror("ioctl(CIOCGSESSION)");
			print "ioctl (CIOCGSESSION) error"
			return False


		if not get_sha1_hmac(cfd, mackey, mackey_len, ciphertext,
					HEADER_SIZE + PLAINTEXT_SIZE + FOOTER_SIZE, sha1mac):
			print "SHA1 MAC failed"
			return False


		if tag[:20] != sha1mac[:20]:
			print "AEAD SHA1 MAC does not match plain MAC"
			print_buf("SHA1: ", sha1mac, 20)
			print_buf("SHA1-SRTP: ", tag, 20)
			return False


		# Decrypt data.encrypted to data.decrypted
		co.ses = sess.ses
		co.len = PLAINTEXT_SIZE
		tmp = c_char_p(addressof(cast(ciphertext, POINTER(c_char)).contents)
					+ HEADER_SIZE) # this is ciphertext + HEADER_SIZE
		co.src = cast(tmp, POINTER(c_uint8))
		tmp = c_char_p(addressof(cast(ciphertext, POINTER(c_char)).contents)
					+ HEADER_SIZE) # this is ciphertext + HEADER_SIZE
		co.dst = cast(tmp, POINTER(c_uint8))
		co.iv = cast(iv, POINTER(c_uint8))
		co.op = COP_DECRYPT
		if libc.ioctl(cfd, CIOCCRYPT, byref(co)):
			#perror("ioctl(CIOCCRYPT)");
			print "ioctl (CIOCCRYPT) error"
			return False


		# Verify the result
		if (plaintext.value[HEADER_SIZE:HEADER_SIZE + PLAINTEXT_SIZE] !=
				ciphertext.value[HEADER_SIZE : HEADER_SIZE + PLAINTEXT_SIZE]):
			print "FAIL: Decrypted data are different from the input data."
			print "plaintext:" + "".join("{:02x}".format(ord(c))
				for c in plaintext.value[HEADER_SIZE:HEADER_SIZE + PLAINTEXT_SIZE])
			print "ciphertext:" + "".join("{:02x}".format(ord(c))
				for c in ciphertext.value[HEADER_SIZE : HEADER_SIZE + PLAINTEXT_SIZE])
			return False


		if debug:
			print "Test passed"

		# Finish crypto session
		if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
			#perror("ioctl(CIOCFSESSION)");
			print "ioctl (CIOCGSESSION) error"
			return False


		return True
	except Exception, e:
		print str(e)
		print format_exc()
		return False


def test_encrypt_decrypt(cfd):
	try:
		plaintext_raw = create_string_buffer(DATA_SIZE + 63)
		plaintext = c_char_p()
		ciphertext_raw = create_string_buffer(DATA_SIZE + 63)
		ciphertext = c_char_p()
		iv = create_string_buffer(BLOCK_SIZE)
		key = create_string_buffer(KEY_SIZE)
		tag = create_string_buffer(20)
		mackey = create_string_buffer("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")
		mackey_len = 16

		sess = session_op()
		cao = crypt_auth_op()
		siop = session_info_op()

		memset(byref(sess), 0, sizeof(sess))
		memset(byref(cao), 0, sizeof(cao))

		memset(byref(key),0x33,  sizeof(key))
		memset(byref(iv), 0x03,  sizeof(iv))

		# Get crypto session for AES128
		sess.cipher = CRYPTO_AES_CTR
		sess.keylen = KEY_SIZE
		sess.key = cast(key, POINTER(c_uint8))

		sess.mac = CRYPTO_SHA1_HMAC
		sess.mackeylen = mackey_len
		sess.mackey = cast(mackey, POINTER(c_uint8))

		if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
			#perror("ioctl(CIOCGSESSION)");
			print "ioctl (CIOCGSESSION) error"
			return False


		siop.ses = sess.ses
		if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)):
			#perror("ioctl(CIOCGSESSINFO)");
			print "ioctl (CIOCGSESSINFO) error"
			return False

		# print "requested cipher CRYPTO_AES_CBC/HMAC-SHA1, got %s with driver %s" % (
		#		siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name)

		plaintext.value = (addressof(plaintext_raw) + siop.alignmask) & ~siop.alignmask
		ciphertext.value = (addressof(ciphertext_raw) + siop.alignmask) & ~siop.alignmask

		memset(plaintext, 0x15, HEADER_SIZE) # header
		memset(c_char_p(addressof(cast(plaintext, POINTER(c_char)).contents)
				+ HEADER_SIZE), 0x17, PLAINTEXT_SIZE) # payload
		memset(c_char_p(addressof(cast(plaintext, POINTER(c_char)).contents)
				+ HEADER_SIZE + PLAINTEXT_SIZE), 0x22, FOOTER_SIZE)

		memmove(ciphertext, plaintext, DATA_SIZE);

		# Encrypt data.in to data.encrypted
		cao.ses = sess.ses
		cao.len = PLAINTEXT_SIZE
		cao.auth_len = HEADER_SIZE+PLAINTEXT_SIZE+FOOTER_SIZE
		cao.auth_src = cast(ciphertext, POINTER(c_uint8))
		tmp = c_char_p(addressof(cast(ciphertext, POINTER(c_char)).contents)
					+ HEADER_SIZE) # this is ciphertext + HEADER_SIZE
		cao.src = cast(tmp, POINTER(c_uint8))
		cao.dst = cao.src
		cao.iv = cast(iv, POINTER(c_uint8))
		cao.op = COP_ENCRYPT
		cao.flags = COP_FLAG_AEAD_SRTP_TYPE
		cao.tag = cast(tag, POINTER(c_uint8))
		cao.tag_len = 20;

		if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)):
			#perror("ioctl(CIOCAUTHCRYPT)");
			print "ioctl (CIOCAUTHCRYPT) error"
			return False



		if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
			#perror("ioctl(CIOCFSESSION)");
			print "ioctl (CIOCFSESSION) error"
			return False


		# Get crypto session for AES128
		memset(byref(sess), 0, sizeof(sess))
		sess.cipher = CRYPTO_AES_CTR
		sess.keylen = KEY_SIZE
		sess.key = cast(key, POINTER(c_uint8))

		sess.mac = CRYPTO_SHA1_HMAC
		sess.mackeylen = mackey_len
		sess.mackey = cast(mackey, POINTER(c_uint8))

		if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
			#perror("ioctl(CIOCGSESSION)");
			print "ioctl (CIOCGSESSION) error"
			return False


		# Decrypt data.encrypted to data.decrypted
		# Encrypt data.in to data.encrypted
		cao.ses = sess.ses
		cao.len = PLAINTEXT_SIZE
		cao.auth_len = HEADER_SIZE+PLAINTEXT_SIZE+FOOTER_SIZE
		cao.auth_src = cast(ciphertext, POINTER(c_uint8))
		tmp = c_char_p(addressof(cast(ciphertext, POINTER(c_char)).contents)
					+ HEADER_SIZE) # this is ciphertext + HEADER_SIZE
		cao.src = cast(tmp, POINTER(c_uint8))
		cao.dst = cao.src
		cao.iv = cast(iv, POINTER(c_uint8))
		cao.op = COP_DECRYPT
		cao.flags = COP_FLAG_AEAD_SRTP_TYPE
		cao.tag = cast(tag, POINTER(c_uint8))
		cao.tag_len = 20
		if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)):
			#perror("ioctl(CIOCCRYPT)");
			print "ioctl () error"
			return False


		# Verify the result
		if (plaintext.value[HEADER_SIZE:HEADER_SIZE + PLAINTEXT_SIZE] !=
				ciphertext.value[HEADER_SIZE : HEADER_SIZE + PLAINTEXT_SIZE]):
			print "FAIL: Decrypted data are different from the input data."
			print "plaintext:" + "".join("{:02x}".format(ord(c))
				for c in plaintext.value[HEADER_SIZE:HEADER_SIZE + PLAINTEXT_SIZE])
			print "ciphertext:" + "".join("{:02x}".format(ord(c))
				for c in ciphertext.value[HEADER_SIZE : HEADER_SIZE + PLAINTEXT_SIZE])
			return False


		if debug:
			print "Test passed"


		# Finish crypto session
		if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
			#perror("ioctl(CIOCFSESSION)");
			print "ioctl (CIOCFSESSION) error"
			return False


		return True
	except Exception, e:
		print str(e)
		print format_exc()
		return False


def test_encrypt_decrypt_error(cfd, err):
	try:
		plaintext_raw = create_string_buffer(DATA_SIZE + 63)
		plaintext = c_char_p()
		ciphertext_raw = create_string_buffer(DATA_SIZE + 63)
		ciphertext = c_char_p()
		iv = create_string_buffer(BLOCK_SIZE)
		key = create_string_buffer(KEY_SIZE)
		tag = create_string_buffer(20)
		mackey = create_string_buffer("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")
		mackey_len = 16

		sess = session_op()
		cao = crypt_auth_op()
		siop = session_info_op()

		memset(byref(sess), 0, sizeof(sess))
		memset(byref(cao), 0, sizeof(cao))

		memset(byref(key),0x33,  sizeof(key))
		memset(byref(iv), 0x03,  sizeof(iv))

		# Get crypto session for AES128
		sess.cipher = CRYPTO_AES_CTR
		sess.keylen = KEY_SIZE
		sess.key = cast(key, POINTER(c_uint8))

		sess.mac = CRYPTO_SHA1_HMAC
		sess.mackeylen = mackey_len
		sess.mackey = cast(mackey, POINTER(c_uint8))

		if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
			#perror("ioctl(CIOCGSESSION)");
			print "ioctl (CIOCGSESSION) error"
			return False


		siop.ses = sess.ses
		if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)):
			#perror("ioctl(CIOCGSESSINFO)");
			print "ioctl (CIOCGSESSINFO) error"
			return False

		# printf("requested cipher CRYPTO_AES_CBC/HMAC-SHA1, got %s with driver %s" % (
		#		siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name)

		plaintext.value = (addressof(plaintext_raw) + siop.alignmask) & ~siop.alignmask
		ciphertext.value = (addressof(ciphertext_raw) + siop.alignmask) & ~siop.alignmask

		memset(plaintext, 0x15, HEADER_SIZE); # header
		memset(c_char_p(addressof(cast(plaintext, POINTER(c_char)).contents)
				+ HEADER_SIZE), 0x17, PLAINTEXT_SIZE) # payload
		memset(c_char_p(addressof(cast(plaintext, POINTER(c_char)).contents)
				+ HEADER_SIZE + PLAINTEXT_SIZE), 0x22, FOOTER_SIZE)

		memmove(ciphertext, plaintext, DATA_SIZE);

		# Encrypt data.in to data.encrypted
		cao.ses = sess.ses
		cao.len = PLAINTEXT_SIZE
		cao.auth_len = HEADER_SIZE+PLAINTEXT_SIZE+FOOTER_SIZE
		cao.auth_src = cast(ciphertext, POINTER(c_uint8))
		tmp = c_char_p(addressof(cast(ciphertext, POINTER(c_char)).contents)
					+ HEADER_SIZE) # this is ciphertext + HEADER_SIZE
		cao.src = cast(tmp, POINTER(c_uint8))
		cao.dst = cao.src
		cao.iv = cast(iv, POINTER(c_uint8))
		cao.op = COP_ENCRYPT
		cao.flags = COP_FLAG_AEAD_SRTP_TYPE
		cao.tag = cast(tag, POINTER(c_uint8))
		cao.tag_len = 20

		if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)):
			#perror("ioctl(CIOCAUTHCRYPT)");
			print "ioctl (CIOCAUTHCRYPT) error"
			return False



		if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
			#perror("ioctl(CIOCFSESSION)");
			print "ioctl (CIOCFSESSION) error"
			return False


		# Get crypto session for AES128
		memset(byref(sess), 0, sizeof(sess))
		sess.cipher = CRYPTO_AES_CTR
		sess.keylen = KEY_SIZE
		sess.key = cast(key, POINTER(c_uint8))

		sess.mac = CRYPTO_SHA1_HMAC
		sess.mackeylen = mackey_len
		sess.mackey = cast(mackey, POINTER(c_uint8))

		if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
			#perror("ioctl(CIOCGSESSION)");
			print "ioctl (CIOCGSESSION) error"
			return False


		# Decrypt data.encrypted to data.decrypted
		# Encrypt data.in to data.encrypted
		if err == 0:
			# The following code is equivalent to ciphertext[1]++;
			cast(ciphertext, POINTER(c_byte))[1] += 1
		else:
			# The following code is equivalent to ciphertext[HEADER_SIZE+3]++;
			cast(ciphertext, POINTER(c_byte))[HEADER_SIZE + 3] += 1


		cao.ses = sess.ses
		cao.len = PLAINTEXT_SIZE
		cao.auth_len = HEADER_SIZE+PLAINTEXT_SIZE+FOOTER_SIZE
		cao.auth_src = cast(ciphertext, POINTER(c_uint8))
		tmp = c_char_p(addressof(cast(ciphertext, POINTER(c_char)).contents)
					+ HEADER_SIZE) # this is ciphertext + HEADER_SIZE
		cao.src = cast(tmp, POINTER(c_uint8))
		cao.dst = cao.src
		cao.iv = cast(iv, POINTER(c_uint8))
		cao.op = COP_DECRYPT
		cao.flags = COP_FLAG_AEAD_SRTP_TYPE
		cao.tag = cast(tag, POINTER(c_uint8))
		cao.tag_len = 20

		if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)):
			if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
				#perror("ioctl(CIOCFSESSION)");
				print "ioctl (CIOCFSESSION) error"
				return False


			if debug:
				print "Test passed"
			return True


		# Verify the result
		if (plaintext.value[HEADER_SIZE:HEADER_SIZE + PLAINTEXT_SIZE] !=
				ciphertext.value[HEADER_SIZE : HEADER_SIZE + PLAINTEXT_SIZE]):
			print "FAIL: Decrypted data are different from the input data."
			print "plaintext:" + "".join("{:02x}".format(ord(c))
				for c in plaintext.value[HEADER_SIZE:HEADER_SIZE + PLAINTEXT_SIZE])
			print "ciphertext:" + "".join("{:02x}".format(ord(c))
				for c in ciphertext.value[HEADER_SIZE : HEADER_SIZE + PLAINTEXT_SIZE])
			return False


		print "Test failed"


		# Finish crypto session
		if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
			#perror("ioctl(CIOCFSESSION)");
			print "ioctl (CIOCFSESSION) error"
			return False


		return False
	except Exception, e:
		print str(e)
		print format_exc()
		return False


def main():
	try:
		fd, cfd = c_uint(-1), c_uint(-1)

		#if (argc > 1) debug = 1;

		# Open the crypto device
		fd.value = open("/dev/crypto", O_RDWR, 0)

		# Clone file descriptor
		if libc.ioctl(fd, CRIOGET, byref(cfd)):
			#perror("ioctl(CRIOGET)");
			print "ioctl () error"
			return False


		# Set close-on-exec (not really neede here)
		if libc.fcntl(cfd.value, F_SETFD, 1) == -1:
			#perror("fcntl(F_SETFD)");
			print "fcntl (F_SETFD) error"
			return False


		# Run the test itself

		if not test_crypto(cfd.value):
			return False

		if not test_encrypt_decrypt(cfd.value):
			return False

		if not test_encrypt_decrypt_error(cfd.value,0):
			return False

		if not test_encrypt_decrypt_error(cfd.value,1):
			return False

		# Close cloned descriptor
		close(cfd.value)

		# Close the original descriptor
		close(fd.value)

		return True
	except Exception, e:
		print str(e)
		print format_exc()
		return False

if __name__ == "__main__":
	main()

