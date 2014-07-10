from ctypes import create_string_buffer, addressof, memset, sizeof, cast, c_char_p, c_int, c_uint32, POINTER, byref, memmove, CDLL
from cryptodev import *
from fcntl import F_SETFD
from os import open, close, O_RDWR
from traceback import format_exc

libc = CDLL("libc.so.6")
debug = True;

DATA_SIZE = 8*1024
BLOCK_SIZE = 16
KEY_SIZE = 16

def test_crypto(cfd):
    __func__ = "test crypto"
    try:

        plaintext_raw = create_string_buffer(DATA_SIZE + 63)
        plaintext = c_char_p()
        ciphertext_raw = create_string_buffer(DATA_SIZE + 63)
        ciphertext = c_char_p()
        iv = create_string_buffer(BLOCK_SIZE)
        key = create_string_buffer(KEY_SIZE)

        sess = session_op()
        siop = session_info_op()
        cryp = crypt_op()
        if debug:
            print "running %s\n" % __func__

        memset(byref(sess), 0, sizeof(sess))
        memset(byref(cryp), 0, sizeof(cryp))

        memset(byref(key), 0x33,  sizeof(key))
        memset(byref(iv), 0x03,  sizeof(iv))
        # Get crypto session for AES128
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEY_SIZE
        sess.key = cast(key, POINTER(c_uint8))
        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)) != 0:
            #perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
            return False

#ifdef CIOCGSESSINFO
        siop.ses = sess.ses
        if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)) != 0:
            #perror("ioctl(CIOCGSESSINFO)")
            print "ioctl(CIOCGSESSINFO) error"
            return False

        if debug:
            print "requested cipher CRYPTO_AES_CBC, got %s with driver %s" % (siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name)

        plaintext.value = (addressof(plaintext_raw) + siop.alignmask) & ~siop.alignmask
        ciphertext.value = (addressof(ciphertext_raw) + siop.alignmask) & ~siop.alignmask

#else
        #plaintext.value = byref(plaintext_raw)
        #ciphertext.value = byref(ciphertext_raw)

#endif
        memset(plaintext, 0x15, DATA_SIZE)

        # Encrypt data.in to data.encrypted.
        cryp.ses = sess.ses
        cryp.len = DATA_SIZE
        cryp.src = cast(plaintext, POINTER(c_uint8))
        cryp.dst = cast(ciphertext, POINTER(c_uint8))
        cryp.iv = cast(iv, POINTER(c_uint8))
        cryp.op = COP_ENCRYPT

        if libc.ioctl(cfd, CIOCCRYPT, byref(cryp)) != 0:
            #perror("ioctl(CIOCCRYPT)")
            print "ioctl(CIOCCRYPT) error"
            return False

        if libc.ioctl(cfd, CIOCFSESSION, byref(sess), session_op.ses.offset) != 0:
            #perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
            return False

        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)) !=0:
            #perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
            return False

        siop.ses = sess.ses
        if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)) != 0:
            #perror("ioctl(CIOCGSESSINFO)")
            print "ioctl(CIOCGSESSINFO) error"
            return False

        if debug:
            print "requested cipher CRYPTO_AES_CBC, got %s with driver %s" % (siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name)

        # Decrypt data.encrypted to data.decrypted.
        cryp.ses = sess.ses
        cryp.len = DATA_SIZE
        cryp.src = cast(ciphertext, POINTER(c_uint8))
        cryp.dst = cast(ciphertext, POINTER(c_uint8))
        cryp.iv = cast(iv, POINTER(c_uint8))
        cryp.op = COP_DECRYPT

        if libc.ioctl(cfd, CIOCCRYPT, byref(cryp)) != 0:
            #perror("ioctl(CIOCCRYPT)")
            print "ioctl(CIOCCRYPT) error"
            return False

        # Verify the result.
        if plaintext.value != ciphertext.value:
            print "FAIL: Decrypted data are different from the input data."
            print "plaintext:"
            print plaintext.value
            print "ciphertext:"
            print ciphertext.value
            return False
        elif debug:
            print "Test passed"

        # Finish crypto session
        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)) != 0:
            #perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
            return False

        return True
    except Exception, e:
        print format_exc()
        return False

def test_aes(cfd):
    try:
        plaintext1_raw = create_string_buffer(BLOCK_SIZE + 63)
        plaintext1 = c_char_p()
        ciphertext1 = create_string_buffer("".join([chr(0xdf), chr(0x55), chr(0x6a), chr(0x33), chr(0x43), chr(0x8d), chr(0xb8), chr(0x7b), chr(0xc4), chr(0x1b), chr(0x17), chr(0x52), chr(0xc5), chr(0x5e), chr(0x5e), chr(0x49)]), BLOCK_SIZE)
        iv1 = create_string_buffer(BLOCK_SIZE)
        key1 = create_string_buffer("".join([chr(0xff), chr(0xff), chr(0xc0), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x00), chr(0x00)]), KEY_SIZE)
        plaintext2_data = create_string_buffer("".join([chr(0xff), chr(0xff), chr(0xff), chr(0xff), chr(0xff), chr(0xff), chr(0xff), chr(0xff), chr(0xff), chr(0xff), chr(0xff), chr(0xff), chr(0xff), chr(0xff), chr(0xc0), chr(0x00)]), BLOCK_SIZE)
        plaintext2_raw = create_string_buffer(BLOCK_SIZE + 63)
        plaintext2 = c_char_p()
        ciphertext2 = create_string_buffer("".join([chr(0xb7), chr(0x97), chr(0x2b), chr(0x39), chr(0x41), chr(0xc4), chr(0x4b), chr(0x90), chr(0xaf), chr(0xa7), chr(0xb2), chr(0x64), chr(0xbf), chr(0xba), chr(0x73), chr(0x87)]), BLOCK_SIZE)
        iv2 = create_string_buffer(BLOCK_SIZE)
        key2 =  create_string_buffer(KEY_SIZE)

        sess = session_op()
        siop =  session_info_op()
        cryp = crypt_op()

        memset(byref(sess), 0, sizeof(sess));
        memset(byref(cryp), 0, sizeof(cryp));

        # Get crypto session for AES128.
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEY_SIZE
        sess.key = cast(key1, POINTER(c_uint8))
        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)) != 0:
            #perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
            return False

#ifdef CIOCGSESSINFO
        siop.ses = sess.ses;
        if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)) != 0:
            #perror("ioctl(CIOCGSESSINFO)")
            print "ioctl(CIOCGSESSINFO) error"
            return False

        #plaintext1 = (char *)(((unsigned long)plaintext1_raw + siop.alignmask) & ~siop.alignmask);
        plaintext1.value = (addressof(plaintext1_raw) + siop.alignmask) & ~siop.alignmask
#else
        #plaintext1.value = byref(plaintext1_raw)
#endif
        memset(plaintext1, 0x0, BLOCK_SIZE)
        memset(byref(iv1), 0x0, sizeof(iv1))
        # Encrypt data.in to data.encrypted
        cryp.ses = sess.ses
        cryp.len = BLOCK_SIZE
        cryp.src = cast(plaintext1, POINTER(c_uint8))
        cryp.dst = cast(plaintext1, POINTER(c_uint8))
        cryp.iv = cast(iv1, POINTER(c_uint8))
        cryp.op = COP_ENCRYPT
        if libc.ioctl(cfd, CIOCCRYPT, byref(cryp)) != 0:
            #perror("ioctl(CIOCCRYPT)")
            print "ioctl(CIOCCRYPT) error"
            return False

        # Verify the result
        if plaintext1.value != ciphertext1.value:
            print "FAIL: Decrypted data are different from the input data."
            return False

        # Test 2

        memset(byref(key2), 0x0, sizeof(key2))
        memset(byref(iv2), 0x0, sizeof(iv2))

        # Get crypto session for AES128
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEY_SIZE
        sess.key = cast(key2, POINTER(c_uint8))
        if libc.ioctl(cfd, CIOCGSESSION, byref(sess)) != 0:
            #perror("ioctl(CIOCGSESSION)")
            print "ioctl(CIOCGSESSION) error"
            return False

#ifdef CIOCGSESSINFO
        siop.ses = sess.ses;
        if libc.ioctl(cfd, CIOCGSESSINFO, byref(siop)) != 0:
            #perror("ioctl(CIOCGSESSINFO)")
            print "ioctl(CIOCGSESSINFO) error"
            return False

        if debug:
            print "requested cipher CRYPTO_AES_CBC, got %s with driver %s" % (siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name)

        #plaintext2 = (char *)(((unsigned long)plaintext2_raw + siop.alignmask) & ~siop.alignmask);
        plaintext2.value = (addressof(plaintext2_raw) + siop.alignmask) & ~siop.alignmask
#else
        #plaintext2 = c_char_p(byref(plaintext2_raw))
#endif
        memmove(plaintext2, byref(plaintext2_data), BLOCK_SIZE);

        # Encrypt data.in to data.encrypted
        cryp.ses = sess.ses;
        cryp.len = BLOCK_SIZE
        cryp.src = cast(plaintext2, POINTER(c_uint8))
        cryp.dst = cast(plaintext2, POINTER(c_uint8))
        cryp.iv = cast(iv2, POINTER(c_uint8))
        cryp.op = COP_ENCRYPT
        if libc.ioctl(cfd, CIOCCRYPT, byref(cryp)) != 0:
            #perror("ioctl(CIOCCRYPT)")
            print "ioctl(CIOCCRYPT) error"
            return False

        # Verify the result
        if plaintext2.value != ciphertext2.value:
            print "FAIL: Decrypted data are different from the input data."
            printf("plaintext:");
            print ":".join("{:02x}".format(ord(c)) for c in plaintext2.value)
            printf("ciphertext:");
            print ":".join("{:02x}".format(ord(c)) for c in ciphertext2.value)
            return False

        if debug:
            print "AES Test passed"

        # Finish crypto session
        if libc.ioctl(cfd, CIOCFSESSION, byref(sess, session_op.ses.offset)) != 0:
            #perror("ioctl(CIOCFSESSION)")
            print "ioctl(CIOCFSESSION) error"
            return False

        return True
    except Exception,e:
        print str(e)
        print format_exc()
        return False

def main():
    try:

        cfd = c_int()
        fd = c_int()
        cfd.value = -1

        #if (argc > 1) debug = 1;

        # Open the crypto device
        fd.value = open("/dev/crypto", O_RDWR, 0)
        # Clone file descriptorn
        # Using c_uint64(byref()) instead of byref because OverFlowError raises
        # http://hg.python.org/cpython/file/bc6d28e726d8/Python/getargs.c#l658
        if libc.ioctl(fd.value, CRIOGET, byref(cfd)) != 0:
            #perror("ioctl(CRIOGET)")
            print "ioctl(CRIOGET) error"
            return False
        # Set close-on-exec (not really neede here)
        if libc.fcntl(cfd.value, F_SETFD, 1) == -1:
            #perror("fcntl(F_SETFD)")
            print "fcntl(F_SETFD) error"
            return False

        #Run the test itself
        if test_aes(cfd.value) == False:
            return False

        if test_crypto(cfd.value) == False:
            return False

        # Close cloned descriptor
        close(cfd.value)

        # Close the original descriptor
        close(fd.value)

        return True
    except OSError, e:
        print str(e)
        return False

if __name__ == "__main__":
    main()

