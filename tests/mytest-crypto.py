"""
First attempt to build a python binding to
communicate with cryptodev using ctypes
cryptodevh.py contains some definitions defined
in cryptodev.h

Author Tilemachos Charalampous <tilemachcharalampous@gmail.com>
"""

# Import useful libs
from cryptodev import (CIOCCRYPT, CIOCGSESSION, COP_ENCRYPT, 
                        COP_DECRYPT, crypt_op, session_op, CRYPTO_AES_CBC, 
                        CIOCFSESSION)
from ctypes import (c_uint16, c_uint32, c_uint8, cast, sizeof, POINTER, 
                    create_string_buffer, byref, CDLL)
from os import open, close, O_RDWR
from traceback import format_exc
from random import choice
from string import ascii_uppercase, digits

libc = CDLL("libc.so.6")
# Define buffer size, key size and block size
BUFSIZE = 512
KEYSIZE = 16
BLOCKSIZE = 16

"""
This is the Data class.
No need to do implement it like a c structure.
"""
class Data:
    def __init__(self, inp, iv, key):
        self.inpt = create_string_buffer(inp, BUFSIZE)
        self.iv = create_string_buffer(iv, BLOCKSIZE)
        self.key = create_string_buffer(key, KEYSIZE)
        self.encrypted = create_string_buffer(BUFSIZE)
        self.decrypted = create_string_buffer(BUFSIZE)

# Function to init session
def get_session(mydata, sess, fd):
    try:
        sess.cipher = CRYPTO_AES_CBC
        sess.keylen = KEYSIZE
        sess.key = cast(mydata.key, POINTER(c_uint8))
        if libc.ioctl(fd, CIOCGSESSION, byref(sess)) != 0:
            print "ioctl (CIOCGSESSION) error"
            exit(1)
    except Exception, e:
        print str(e)
        print format_exc()
        exit(1)

def close_session(sess, fd):
    try:
        if libc.ioctl(fd, CIOCFSESSION, byref(sess, session_op.ses.offset)) != 0:
            print "ioctl (CIOCFSESSION) error"
            exit(1)
    except Exception, e:
        print str(e)
        print format_exc()
        exit(1)    

# Function to encrypt data
def encrypt(mydata, sess, cryp, fd):
    try:
        cryp.ses = sess.ses
        cryp.len = sizeof(mydata.inpt)
        cryp.src = cast(mydata.inpt, POINTER(c_uint8))
        cryp.dst = cast(mydata.encrypted, POINTER(c_uint8))
        cryp.iv = cast(mydata.iv, POINTER(c_uint8))
        cryp.op = COP_ENCRYPT
        if libc.ioctl(fd, CIOCCRYPT, byref(cryp)) != 0:
            print "ioctl (CIOCCRYPT) error"
            exit(1)
    except Exception, e:
        print str(e)
        print format_exc()
        exit(1)

# Function to decrypt data
def decrypt(mydata, sess, cryp, fd):
    try:
        cryp.src = cast(mydata.encrypted, POINTER(c_uint8))
        cryp.dst = cast(mydata.decrypted, POINTER(c_uint8))
        cryp.op = COP_DECRYPT
        if libc.ioctl(fd, CIOCCRYPT, byref(cryp)) != 0:
            print "ioctl (CIOCCRYPT) error"
            exit(1)
    except Exception, e:
        print str(e)
        print format_exc()
        exit(1)

# Function to print data in hex
def print_message(msg1, msg2):
    hexMsg = ":".join("{:02x}".format(ord(c)) for c in msg2 if c != '\0')
    print "*" * 100
    print msg1 + " (hex)\n%s\n" % hexMsg
    print "*" * 100

#Function to get the string from a string buffer by keeping all non null characters of the string
def get_string(buf):
    return "".join(c for c in buf if c != '\0')

# useful function to generate random string
def random_string(size, chars=ascii_uppercase + digits):
    return ''.join(choice(chars) for _ in range(size))

# Function to test encryption/decryption
def test(fd):
    inpt = random_string(BUFSIZE)
    key = random_string(KEYSIZE)
    iv = random_string(BLOCKSIZE)

    mydata = Data(inpt, iv, key)
    sess = session_op()
    cryp = crypt_op()

    get_session(mydata, sess, fd)
    print_message("Original data", mydata.inpt)
    encrypt(mydata, sess, cryp, fd)
    print_message("Encrypted data", mydata.encrypted)
    decrypt(mydata, sess, cryp, fd)
    print_message("Decrypted data", mydata.decrypted)
    if get_string(mydata.decrypted) == get_string(mydata.inpt.value):
        print "Sucess!"
    else:
        print "Looser@"
    close_session(sess, fd)


# Main function
def main():
    try:
        fd = open("/dev/crypto", O_RDWR)
        test(fd)
        close(fd)
    except OSError, e:
        print str(type(e)) + str(e)
    except Exception, e:
        print str(type(e)) + str(e)
        print traceback.format_exc()

if __name__ == "__main__":
    main()
