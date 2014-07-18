'''
This is a Python rip from cipher-gcm.c.
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

from cryptodev import *
from ctypes import POINTER, byref, addressof, Structure, c_uint8, c_int, create_string_buffer, c_int8, c_char_p, cast, c_byte, CDLL, memset, memmove
from fcntl import F_SETFD
from os import open, close, O_RDWR
from traceback import format_exc

libc = CDLL("libc.so.6")
DATA_SIZE = (8*1024)
AUTH_SIZE = 31
BLOCK_SIZE = 16
KEY_SIZE = 16

def my_perror(x):
    print "%s: %d\n" % (__func__, __LINE__)
    print x

debug = True

def print_buf(desc, buf, size):
    print desc + "".join("{:02x}".format(ord(c)) for c in buf.value[:size])

class aes_gcm_vectors_st(Structure):
    _fields_ = [("key", POINTER(c_uint8)),
                ("auth", POINTER(c_uint8)),
                ("auth_size", c_int),
                ("plaintext", POINTER(c_uint8)),
                ("plaintext_size", c_int),
                ("iv", POINTER(c_uint8)),
                ("ciphertext", POINTER(c_uint8)),
                ("tag", POINTER(c_uint8))]

aes_gcm_vectors = (3 * aes_gcm_vectors_st)()
tmp = aes_gcm_vectors_st()
tmp.key = cast(create_string_buffer("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), POINTER(c_uint8))
tmp.auth = None
tmp.auth_size = 0
tmp.plaintext = cast(create_string_buffer("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), POINTER(c_uint8))
tmp.plaintext_size = 16
tmp.ciphertext = cast(create_string_buffer("\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78"), POINTER(c_uint8))
tmp.iv = cast(create_string_buffer("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), POINTER(c_uint8))
tmp.tag = cast(create_string_buffer("\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf"), POINTER(c_uint8))

aes_gcm_vectors[0] = tmp

tmp = aes_gcm_vectors_st()
tmp.key = cast(create_string_buffer("\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"), POINTER(c_uint8))
tmp.auth = None
tmp.auth_size = 0
tmp.plaintext = cast(create_string_buffer("\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55"), POINTER(c_uint8))
tmp.plaintext_size = 64
tmp.ciphertext = cast(create_string_buffer("\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91\x47\x3f\x59\x85"), POINTER(c_uint8))
tmp.iv = cast(create_string_buffer("\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88"), POINTER(c_uint8))
tmp.tag = cast(create_string_buffer("\x4d\x5c\x2a\xf3\x27\xcd\x64\xa6\x2c\xf3\x5a\xbd\x2b\xa6\xfa\xb4"), POINTER(c_uint8))

aes_gcm_vectors[1] = tmp

tmp = aes_gcm_vectors_st()
tmp.key = cast(create_string_buffer("\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"), POINTER(c_uint8))
tmp.auth = cast(create_string_buffer("\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2"), POINTER(c_uint8))
tmp.auth_size = 20
tmp.plaintext = cast(create_string_buffer("\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39"), POINTER(c_uint8))
tmp.plaintext_size = 60
tmp.ciphertext = cast(create_string_buffer("\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91"), POINTER(c_uint8))
tmp.iv = cast(create_string_buffer("\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88"), POINTER(c_uint8))
tmp.tag = cast(create_string_buffer("\x5b\xc9\x4f\xbc\x32\x21\xa5\xdb\x94\xfa\xe9\x5a\xe7\x12\x1a\x47"), POINTER(c_uint8))

aes_gcm_vectors[2] = tmp

# Test against AES-GCM test vectors.

def test_crypto(cfd):
    try:
        #int i;
        #int8_t tmp[128];
        #tmp = (c_int8 * 128)()
        tmp = create_string_buffer(128)

        sess = session_op()
        cao = crypt_auth_op()

        # Get crypto session for AES128

        if debug:
            print "Tests on AES-GCM vectors: ",

        for i in xrange(sizeof(aes_gcm_vectors) / sizeof(aes_gcm_vectors[0])):
            memset(byref(sess), 0, sizeof(sess))
            memset(byref(tmp), 0, sizeof(tmp))

            sess.cipher = CRYPTO_AES_GCM
            sess.keylen = 16
            sess.key = cast(aes_gcm_vectors[i].key, POINTER(c_uint8))

            if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
                #my_perror("ioctl(CIOCGSESSION) error")
                print "ioctl(CIOCGSESSION) error"
                return False

            memset(byref(cao), 0, sizeof(cao));

            cao.ses = sess.ses
            cao.dst = cast(tmp, POINTER(c_uint8))
            cao.iv = cast(aes_gcm_vectors[i].iv, POINTER(c_uint8))
            cao.iv_len = 12
            cao.op = COP_ENCRYPT
            cao.flags = 0

            if aes_gcm_vectors[i].auth_size > 0:
                cao.auth_src = cast(aes_gcm_vectors[i].auth, POINTER(c_uint8))
                cao.auth_len = aes_gcm_vectors[i].auth_size

            if aes_gcm_vectors[i].plaintext_size > 0:
                cao.src = cast(aes_gcm_vectors[i].plaintext, POINTER(c_uint8))
                cao.len = aes_gcm_vectors[i].plaintext_size

            if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)):
                #my_perror("ioctl(CIOCAUTHCRYPT)");
                print "ioctl(CIOCAUTHCRYPT) error"
                return False

            tmp_string = cast(aes_gcm_vectors[i].ciphertext, c_char_p).value
            if aes_gcm_vectors[i].plaintext_size > 0:
                if  tmp.value[:aes_gcm_vectors[i].plaintext_size] != tmp_string[:aes_gcm_vectors[i].plaintext_size]:
                    print"AES-GCM test vector %d failed!" % i

                    print_buf("Cipher: ", tmp, aes_gcm_vectors[i].plaintext_size);
                    print_buf("Expected: ", tmp_string, aes_gcm_vectors[i].plaintext_size);
                    return False

            offset = cao.len - cao.tag_len
            tmp_string = cast(aes_gcm_vectors[i].tag, c_char_p).value
            if tmp.value[offset : 16 + offset] != tmp_string[:16]:
                print "AES-GCM test vector %d failed (tag)!" % i

                print_buf("Tag: ", tmp, cao.tag_len)
                print_buf("Expected tag: ", aes_gcm_vectors[i].tag, 16);
                return False

        if debug:
            print "ok"

        # Finish crypto session
        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
            #my_perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
            return False
        return True
    except Exception, e:
        print str(e)
        print format_exc()
        return False


'''
Checks if encryption and subsequent decryption
produces the same data.
'''
def test_encrypt_decrypt(cfd):
    try:
        plaintext_raw = create_string_buffer(DATA_SIZE + 63)
        plaintext = c_char_p()
        ciphertext_raw = create_string_buffer(DATA_SIZE + 63)
        ciphertext = c_char_p()
        iv = create_string_buffer(BLOCK_SIZE)
        key = create_string_buffer(KEY_SIZE)
        auth = create_string_buffer(AUTH_SIZE)

        sess = session_op()
        cao = crypt_auth_op()
        siop = session_info_op()

        if debug:
            print "Tests on AES-GCM encryption/decryption: ",

        memset(byref(sess), 0, sizeof(sess))
        memset(byref(cao), 0, sizeof(cao))

        memset(byref(key), 0x33, sizeof(key))
        memset(byref(iv), 0x03, sizeof(iv))
        memset(byref(auth), 0xf1, sizeof(auth))

        # Get crypto session for AES128
        sess.cipher = CRYPTO_AES_GCM
        sess.keylen = KEY_SIZE
        sess.key = cast(key, POINTER(c_uint8))

        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
            #my_perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
            return False

        siop.ses = sess.ses
        if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)):
            #my_perror("ioctl(CIOCGSESSINFO)")
            print "ioctl(CIOCGSESSINFO) error"
            return False
        # printi "requested cipher CRYPTO_AES_CBC/HMAC-SHA1, got %s with driver %s" % (siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name)

        plaintext.value = (addressof(plaintext_raw) + siop.alignmask) & ~siop.alignmask
        ciphertext.value = (addressof(ciphertext_raw) + siop.alignmask) & ~siop.alignmask

        memset(plaintext, 0x15, DATA_SIZE)

        # Encrypt data.in to data.encrypted
        cao.ses = sess.ses
        cao.auth_src = cast(auth, POINTER(c_uint8))
        cao.auth_len = sizeof(auth)
        cao.len = DATA_SIZE
        cao.src = cast(plaintext, POINTER(c_uint8))
        cao.dst = cast(ciphertext, POINTER(c_uint8))
        cao.iv = cast(iv, POINTER(c_uint8))
        cao.iv_len = 12
        cao.op = COP_ENCRYPT
        cao.flags = 0

        if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)):
            #my_perror("ioctl(CIOCAUTHCRYPT)")
            print "ioctl(CIOCAUTHCRYPT) error"
            return False

        enc_len = cao.len
        #printf("Original plaintext size: %d, ciphertext: %d" % (DATA_SIZE, enc_len)

        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
            #my_perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION)"
            return False

        # Get crypto session for AES128
        memset(byref(sess), 0, sizeof(sess))
        sess.cipher = CRYPTO_AES_GCM
        sess.keylen = KEY_SIZE
        sess.key = cast(key, POINTER(c_uint8))

        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
            #my_perror("ioctl(CIOCGSESSION)")
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
        cao.iv_len = 12
        cao.op = COP_DECRYPT
        cao.flags = 0

        if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)):
            #my_perror("ioctl(CIOCAUTHCRYPT)")
            print "in here"
            print "ioctl(CIOCAUTHCRYPT) error"
            return False

        if cao.len != DATA_SIZE:
            print "decrypted data size incorrect!"
            return False

        # Verify the result
        if plaintext.value[:DATA_SIZE] != ciphertext.value[:DATA_SIZE]:
                print "FAIL: Decrypted data are different from the input data."
                print "plaintext:" + "".join("{:02x}".format(ord(c)) for c in plaitext.value[:DATA_SIZE])
                print "ciphertext:" + "".join("{:02x}".format(ord(c)) for c in ciphertext.value[:DATA_SIZE])
                return True

        # Finish crypto session
        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
            #my_perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
            return False

        if debug:
            print "ok"

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


        sess = session_op()
        co = crypt_op()
        cao = crypt_auth_op()
        siop = session_info_op()

        if debug:
            print "Tests on AES-GCM tag verification: ",

        memset(byref(sess), 0, sizeof(sess))
        memset(byref(cao), 0, sizeof(cao))
        memset(byref(co), 0, sizeof(co))

        memset(byref(key), 0x33, sizeof(key))
        memset(byref(iv), 0x03, sizeof(iv))
        memset(byref(auth), 0xf1, sizeof(auth))

        # Get crypto session for AES128
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEY_SIZE
        sess.key = cast(key, POINTER(c_uint8))

        sess.mac = CRYPTO_SHA1_HMAC
        sess.mackeylen = 16
        sess.mackey = cast(create_string_buffer("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"), POINTER(c_uint8))

        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
            #my_perror("ioctl(CIOCGSESSION)");
            print "ioctl(CIOCGSESSION)"
            return False

        siop.ses = sess.ses
        if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)):
                #my_perror("ioctl(CIOCGSESSINFO)")
                print "ioctl(CIOCGSESSINFO) error"
                return False
        # print "requested cipher CRYPTO_AES_CBC/HMAC-SHA1, got %s with driver %s" % (siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name)

        plaintext.value = (addressof(plaintext_raw) + siop.alignmask) & ~siop.alignmask
        ciphertext.value = (addressof(ciphertext_raw) + siop.alignmask) & ~siop.alignmask

        memset(plaintext, 0x15, DATA_SIZE)
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

        if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)):
            #my_perror("ioctl(CIOCAUTHCRYPT)")
            print "ioctl(CIOCAUTHCRYPT) error"
            return False

        enc_len = cao.len
        #print "Original plaintext size: %d, ciphertext: %d", DATA_SIZE, enc_len)

        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
            #my_perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
            return False

        # Get crypto session for AES128
        memset(byref(sess), 0, sizeof(sess))
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEY_SIZE
        sess.key = cast(key, POINTER(c_uint8))
        sess.mac = CRYPTO_SHA1_HMAC
        sess.mackeylen = 16
        sess.mackey = cast(create_string_buffer("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"), POINTER(c_uint8))

        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)):
            #my_perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
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
        if libc.ioctl(cfd, CIOCAUTHCRYPT, byref(cao)):
            if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
                #my_perror("ioctl(CIOCFSESSION)")
                print "ioctl(CIOCFSESSION) error"
                return False

            if debug:
                print "ok"
            return True

        # Finish crypto session
        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)):
            #my_perror("ioctl(CIOCFSESSION)")
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
        fd , cfd = c_int(-1), c_int(-1)

        # if (argc > 1) debug = 1;

        # Open the crypto device
        fd.value = open("/dev/crypto", O_RDWR, 0);

        # Clone file descriptor
        if libc.ioctl(fd.value, CRIOGET, byref(cfd)):
            #my_perror("ioctl(CRIOGET)")
            print "ioctl(CRIOGET) error"
            return False

        # Set close-on-exec (not really neede here)
        if libc.fcntl(cfd.value, F_SETFD, 1) == -1:
            #my_perror("fcntl(F_SETFD)");
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

        return True
    except Exception, e:
        print str(e)
        print format_exc()
        return True

if __name__ == "__main__":
    main()
