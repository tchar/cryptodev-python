'''
This is a Python rip from cipher-aead.c.
Some useful info following:
We are using libc's ioctl and fcnt instead of fcntl's because sometimes addressof()
returns really big numbers. This causes problems to fcntl's ioctl (for more follow the link below):
http://hg.python.org/cpython/file/bc6d28e726d8/Python/getargs.c#l659
fcntl's ioctl/fcntl won't accent ctypes' byref() (another reason to use libc's ioctl/fcntl).
Brief documentation of byref(), addressof() and POINTER() usage:
    byre()f:    Used to pass any reference (light pointer() object) to ioctl/fcntl.
                Used when calling libc's ioctl and not fcntl's ioctl
    addressof():Used to get the real address of a ctypes object. This is used only
                when translate specific C code into Python code (C code is similar to the following):
                plaintext = (char *)(((unsigned long)plaintext_raw + siop.alignmask) & ~siop.alignmask);
    POINTER():  Used when casting a ctypes object to a POINTER object (of a ctype object).
                Mostly used when casting to POINTER(c_uint8)

Author: Tilemachos Charalampous <tilemachos.charalampous@gmail.com>
'''
'''
Demo on how to use /dev/crypto device for ciphering.

Placed under public domain.

'''

from cryptodev import *
from ctypes import CDLL, byref, sizeof, POINTER, c_uint8, create_string_buffer, memset, c_uint, c_char_p, cast, addressof, memmove, c_ubyte, c_byte
from os import open, O_RDWR, close
from fcntl import F_SETFD
from traceback import format_exc

libc = CDLL("libc.so.6")
DATA_SIZE = 8*1024
AUTH_SIZE = 31
BLOCK_SIZE = 16
KEY_SIZE = 16

MAC_SIZE = 20 # SHA1

debug = True

def get_sha1_hmac(cfd, key, key_size, data1, data1_size, data2, data2_size, mac):
    try:
        sess =  session_op()
        cryp = crypt_op()

        memset(byref(sess), 0, sizeof(sess))
        memset(byref(cryp), 0, sizeof(cryp))

        sess.cipher = 0
        sess.mac = CRYPTO_SHA1_HMAC
        sess.mackeylen = key_size
        sess.mackey = cast(key, POINTER(c_uint8))
        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)) != 0:
            #perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
            return False

        # Encrypt data.in to data.encrypted
        cryp.ses = sess.ses
        cryp.len = data1_size
        cryp.src = cast(data1, POINTER(c_uint8))
        cryp.dst = cast(None, POINTER(c_uint8))
        cryp.iv = cast(None, POINTER(c_uint8))
        cryp.mac = cast(mac, POINTER(c_uint8))
        cryp.op = COP_ENCRYPT
        cryp.flags = COP_FLAG_UPDATE
        if libc.ioctl(cfd, CIOCCRYPT, byref(cryp)) != 0:
            #perror("ioctl(CIOCCRYPT)")
            print "ioctl(CIOCCRYPT) error"
            return False

        cryp.ses = sess.ses
        cryp.len = data2_size
        cryp.src = cast(data2, POINTER(c_uint8))
        cryp.dst = cast(None, POINTER(c_uint8))
        cryp.iv = cast(None, POINTER(c_uint8))
        cryp.mac = cast(mac, POINTER(c_uint8))
        cryp.op = COP_ENCRYPT
        cryp.flags = COP_FLAG_FINAL
        if libc.ioctl(cfd, CIOCCRYPT, byref(cryp)) != 0:
            #perror("ioctl(CIOCCRYPT)")
            print "ioctl(CIOCCRYPT) error"
            return False

        # Finish crypto session
        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)) != 0:
            #perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
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
        auth = create_string_buffer(AUTH_SIZE)
        sha1mac = create_string_buffer(20)

        sess = session_op()
        co = crypt_op()
        cao = crypt_auth_op()
        siop = session_info_op()

        memset(byref(sess), 0, sizeof(sess));
        memset(byref(cao), 0, sizeof(cao));
        memset(byref(co), 0, sizeof(co));

        memset(byref(key),0x33,  sizeof(key));
        memset(byref(iv), 0x03,  sizeof(iv));
        memset(byref(auth), 0xf1,  sizeof(auth));
        memset(byref(sha1mac), 0x00, sizeof(sha1mac))

        # Get crypto session for AES128
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEY_SIZE
        sess.key = cast(key, POINTER(c_uint8))

        sess.mac = CRYPTO_SHA1_HMAC
        sess.mackeylen = 16
        sess.mackey = cast(create_string_buffer("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", sess.mackeylen), POINTER(c_uint8))
        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)) != 0:
            #perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
            return False

        siop.ses = sess.ses
        if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)) != 0:
            #perror("ioctl(CIOCGSESSINFO)");
            print "ioctl(CIOCGSESSINFO) error"
            return False

        if debug:
            print "requested cipher CRYPTO_AES_CBC/HMAC-SHA1, got %s with driver %s" % (siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name)

        plaintext.value = (addressof(plaintext_raw) + siop.alignmask) & ~siop.alignmask
        ciphertext.value = (addressof(ciphertext_raw) + siop.alignmask) & ~siop.alignmask
        memset(plaintext, 0x15, DATA_SIZE)

        if get_sha1_hmac(cfd, sess.mackey, sess.mackeylen, auth, sizeof(auth), plaintext, DATA_SIZE, sha1mac) != True:
            print "SHA1 MAC failed"
            return False

        memmove(ciphertext, plaintext, DATA_SIZE);

        # Encrypt data.in to data.encrypted
        cao.ses = sess.ses
        cao.auth_src = cast(auth, POINTER(c_uint8))
        cao.auth_len = sizeof(auth)
        cao.len = DATA_SIZE
        cao.src = cast(ciphertext, POINTER(c_uint8))
        cao.dst = cast(ciphertext, POINTER(c_uint8))
        cao.iv = cast(iv, POINTER(c_uint8))
        cao.op = COP_ENCRYPT
        cao.flags = COP_FLAG_AEAD_TLS_TYPE

        if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)) != 0:
            #perror("ioctl(CIOCAUTHCRYPT)")
            print "ioctl(CIOCAUTHCRYPT) error"
            return False

        #print "Original plaintext size: %d, ciphertext: %d" % (DATA_SIZE, cao.len)

        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)) != 0:
            #perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
            return False

        # Get crypto session for AES128
        memset(byref(sess), 0, sizeof(sess))
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEY_SIZE
        sess.key = cast(key, POINTER(c_uint8))

        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)) != 0:
            #perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
            return False

        # Decrypt data.encrypted to data.decrypted
        co.ses = sess.ses
        co.len = cao.len
        co.src = cast(ciphertext, POINTER(c_uint8))
        co.dst = cast(ciphertext, POINTER(c_uint8))
        co.iv = cast(iv, POINTER(c_uint8))
        co.op = COP_DECRYPT
        if libc.ioctl(cfd, CIOCCRYPT, byref(co)) != 0:
            #perror("ioctl(CIOCCRYPT)")
            print "ioctl(CIOCCRYPT) error"
            return False

        # Verify the result
        if plaintext.value[:DATA_SIZE] != ciphertext.value[:DATA_SIZE]:
            print "FAIL: Decrypted data are different from the input data."
            print "plaintext:" + "".join("{:02x}".format(ord(c)) for c in plaintext.value[:DATA_SIZE])
            print "ciphertext:" + "".join("{:02x}".format(ord(c)) for c in ciphertext.value[:DATA_SIZE])
            return False

        pad = ord(ciphertext.value[cao.len - 1])
        offset = cao.len - MAC_SIZE - pad - 1
        if ciphertext.value[offset : 20 + offset] != sha1mac.value[:20]:
            print "AEAD SHA1 MAC does not match plain MAC"
            print_buf("SHA1: ", sha1mac, 20)
            print_buf("SHA1-TLS: ", create_string_buffer(ciphertext.value[offset:]), 20)
            return False


        for i in xrange(pad):
            if ord(ciphertext.value[cao.len-1-i]) != pad:
                print "Pad does not match (expected %d)" % pad
                print_buf("PAD: ", create_string_buffer(ciphertext.value[cao.len - 1 - pad:]), pad)
                return False

        if debug:
            print "Test passed"


        # Finish crypto session
        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)) != 0:
            #perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
            return False

        return True
    except Exception, e:
        print str(e)
        print format_exc()
        return False

def test_encrypt_decrypt(cfd):
    try:
        plaintext_raw =  create_string_buffer(DATA_SIZE + 63)
        plaintext = c_char_p()
        ciphertext_raw = create_string_buffer(DATA_SIZE + 63)
        ciphertext = c_char_p()
        iv =  create_string_buffer(BLOCK_SIZE)
        key = create_string_buffer(KEY_SIZE)
        auth = create_string_buffer(AUTH_SIZE)
        sha1mac =  create_string_buffer(20)

        sess = session_op()
        co = crypt_op()
        cao = crypt_auth_op()
        siop = session_info_op()

        memset(byref(sess), 0, sizeof(sess))
        memset(byref(cao), 0, sizeof(cao))
        memset(byref(co), 0, sizeof(co))

        memset(byref(key),0x33,  sizeof(key))
        memset(byref(iv), 0x03,  sizeof(iv))
        memset(byref(auth), 0xf1,  sizeof(auth))

        # Get crypto session for AES128
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEY_SIZE
        sess.key = cast(key, POINTER(c_uint8))

        sess.mac = CRYPTO_SHA1_HMAC
        sess.mackeylen = 16
        sess.mackey = cast(create_string_buffer("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", sess.mackeylen), POINTER(c_uint8))

        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)) != 0:
            #perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
            return False

        siop.ses = sess.ses
        if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)) != 0:
            #perror("ioctl(CIOCGSESSINFO)");
            print "ioctl(CIOCGSESSINFO) error"
            return False

        #print "requested cipher CRYPTO_AES_CBC/HMAC-SHA1, got %s with driver %s" % (siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name)

        plaintext.value = (addressof(plaintext_raw) + siop.alignmask) & ~siop.alignmask
        ciphertext.value = (addressof(ciphertext_raw) + siop.alignmask) & ~siop.alignmask

        memset(plaintext, 0x15, DATA_SIZE)

        if get_sha1_hmac(cfd, sess.mackey, sess.mackeylen, auth, sizeof(auth), plaintext, DATA_SIZE, sha1mac) != True:
            #fprintf(stderr, "SHA1 MAC failed\n");
            print "SHA1 MAC failed"
            return False

        memmove(ciphertext, plaintext, DATA_SIZE)

        # Encrypt data.in to data.encrypted
        cao.ses = sess.ses
        cao.auth_src = cast(auth, POINTER(c_uint8))
        cao.auth_len = sizeof(auth)
        cao.len = DATA_SIZE
        cao.src = cast(ciphertext, POINTER(c_uint8))
        cao.dst = cast(ciphertext, POINTER(c_uint8))
        cao.iv = cast(iv, POINTER(c_uint8))
        cao.op = COP_ENCRYPT
        cao.flags = COP_FLAG_AEAD_TLS_TYPE

        if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)) != 0:
            #perror("ioctl(CIOCAUTHCRYPT)")
            print "ioctl(CIOCAUTHCRYPT)"
            return False

        enc_len = cao.len
        # print "Original plaintext size: %d, ciphertext: %d" % (DATA_SIZE, enc_len)

        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)) != 0:
            #perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
            return False

        # Get crypto session for AES128
        memset(byref(sess), 0, sizeof(sess))
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEY_SIZE
        sess.key = cast(key, POINTER(c_uint8))
        sess.mac = CRYPTO_SHA1_HMAC
        sess.mackeylen = 16
        sess.mackey = cast(create_string_buffer("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", sess.mackeylen), POINTER(c_uint8))

        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)) != 0:
            #perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
            return False

        # Decrypt data.encrypted to data.decrypted
        cao.ses = sess.ses
        cao.auth_src = cast(auth, POINTER(c_uint8))
        cao.auth_len = sizeof(auth)
        cao.len = enc_len
        cao.src = cast(ciphertext, POINTER(c_uint8))
        cao.dst = cast(ciphertext, POINTER(c_uint8))
        cao.iv = cast(iv, POINTER(c_uint8))
        cao.op = COP_DECRYPT
        cao.flags = COP_FLAG_AEAD_TLS_TYPE
        if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)) != 0:
            #perror("ioctl(CIOCAUTHCRYPT)")
            print "ioctl(CIOCAUTHCRYPT)"
            return False

        if cao.len != DATA_SIZE:
            print "decrypted data size incorrect!"
            return False

        # Verify the result
        if plaintext.value[:DATA_SIZE] != ciphertext.value[:DATA_SIZE]:
            print "FAIL: Decrypted data are different from the input data."
            print "plaintext:" + "".join("{:02x}".format(ord(c)) for c in plaintext.value[:DATA_SIZE])
            print "ciphertext:" + "".join("{:02x}".format(ord(c)) for c in ciphertext.value[:DATA_SIZE])
            return False

        if debug:
            print "Test passed"


        # Finish crypto session
        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)) != 0:
            #perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
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
        auth = create_string_buffer(AUTH_SIZE)
        sha1mac = create_string_buffer(20)

        sess = session_op()
        co = crypt_op()
        cao = crypt_auth_op()
        siop = session_info_op()

        memset(byref(sess), 0, sizeof(sess))
        memset(byref(cao), 0, sizeof(cao))
        memset(byref(co), 0, sizeof(co))

        memset(byref(key),0x33,  sizeof(key))
        memset(byref(iv), 0x03,  sizeof(iv))
        memset(byref(auth), 0xf1,  sizeof(auth))

        # Get crypto session for AES128
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEY_SIZE
        sess.key = cast(key, POINTER(c_uint8))

        sess.mac = CRYPTO_SHA1_HMAC
        sess.mackeylen = 16
        sess.mackey = cast(create_string_buffer("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", sess.mackeylen), POINTER(c_uint8))

        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)) != 0:
            #perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
            return False

        siop.ses = sess.ses
        if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)) != 0:
            #perror("ioctl(CIOCGSESSINFO)")
            print "ioctl(CIOCGSESSINFO) error"
            return False
        # print "requested cipher CRYPTO_AES_CBC/HMAC-SHA1, got %s with driver %s\n" % (siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name)

        plaintext.value = (addressof(plaintext_raw) + siop.alignmask) & ~siop.alignmask
        ciphertext.value = (addressof(ciphertext_raw) + siop.alignmask) & ~siop.alignmask
        memset(plaintext, 0x15, DATA_SIZE)

        if get_sha1_hmac(cfd, sess.mackey, sess.mackeylen, auth, sizeof(auth), plaintext, DATA_SIZE, sha1mac) != True:
            print "SHA1 MAC failed"
            return False

        memmove(ciphertext, plaintext, DATA_SIZE)

        # Encrypt data.in to data.encrypted
        cao.ses = sess.ses
        cao.auth_src = cast(auth, POINTER(c_uint8))
        cao.auth_len = sizeof(auth)
        cao.len = DATA_SIZE
        cao.src = cast(ciphertext, POINTER(c_uint8))
        cao.dst = cast(ciphertext, POINTER(c_uint8))
        cao.iv = cast(iv, POINTER(c_uint8))
        cao.op = COP_ENCRYPT
        cao.flags = COP_FLAG_AEAD_TLS_TYPE

        if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)) != 0:
            #perror("ioctl(CIOCAUTHCRYPT)")
            print "ioctl(CIOCAUTHCRYPT) error"
            return False

        enc_len = cao.len
        # printf("Original plaintext size: %d, ciphertext: %d" % (DATA_SIZE, enc_len)

        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)) != 0:
            #perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
            return False

        # Get crypto session for AES128
        memset(byref(sess), 0, sizeof(sess))
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEY_SIZE
        sess.key = cast(key, POINTER(c_uint8))
        sess.mac = CRYPTO_SHA1_HMAC
        sess.mackeylen = 16
        sess.mackey = cast(create_string_buffer("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", sess.mackeylen), POINTER(c_uint8))

        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)) != 0:
            #perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION)"
            return False

        if err == 0:
            # The following code is equivalent to auth[2]++;
            cast(auth, POINTER(c_byte))[2] += 1
        else:
            # The following code is equivalent to ciphertext[4]++;
            cast(ciphertext, POINTER(c_byte))[4] += 1

        # Decrypt data.encrypted to data.decrypted
        cao.ses = sess.ses
        cao.auth_src = cast(auth, POINTER(c_uint8))
        cao.auth_len = sizeof(auth)
        cao.len = enc_len
        cao.src = cast(ciphertext, POINTER(c_uint8))
        cao.dst = cast(ciphertext, POINTER(c_uint8))
        cao.iv = cast(iv, POINTER(c_uint8))
        cao.op = COP_DECRYPT
        cao.flags = COP_FLAG_AEAD_TLS_TYPE
        if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)) != 0:
            if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)) != 0:
                #perror("ioctl(CIOCFSESSION)")
                print "ioctl(CIOCFSESSION) error"
                return False

            if debug:
                print "Test passed"

            return True

        # Finish crypto session
        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)) != 0:
            #perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
            return False


        print "Modification to ciphertext was not detected"
        return False
    except Exception, e:
        print str(e)
        print format_exc()
        return False

def main():
    try:
        fd, cfd = c_uint(-1), c_uint(-1)

        # Open the crypto device
        fd.value = open("/dev/crypto", O_RDWR, 0)

        # Clone file descriptor
        if libc.ioctl(fd.value, CRIOGET, byref(cfd)) != 0:
            #perror("ioctl(CRIOGET)")
            print "ioctl(CRIOGET) error"
            return False

        # Set close-on-exec (not really neede here)
        if libc.fcntl(cfd.value, F_SETFD, 1) == -1:
            #perror("fcntl(F_SETFD)")
            print "fcntl(F_SETFD) error"
            return False

        # Run the test itself

        if not test_crypto(cfd.value):
            return False

        if not test_encrypt_decrypt(cfd.value):
           return False

        if not test_encrypt_decrypt_error(cfd.value, 0):
           return False

        if not test_encrypt_decrypt_error(cfd.value, 1):
           return False

        # Close cloned descriptor
        close(cfd.value)

        # Close the original descriptor
        close(fd.value)

    except Exception, e:
        print str(e)
        return False

if __name__ == "__main__":
    main()
