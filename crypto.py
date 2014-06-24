"""
First attempt to build a python binding to
communicate with cryptodev using ctypes
ioctlh contains usefull functions in python
equivalent to ioctl.h's header:
http://lxr.free-electrons.com/source/include/uapi/asm-generic/ioctl.h#L79
Copy of ioctlh can be found here:
from http://code.activestate.com/recipes/578225-linux-ioctl-numbers-in-python/
Created by Dima Tisnek

Author Tilemachos Charalampous <tilemachos.charalampous@gmail.com>
"""

# Import usefull libs
import ioctlh
import fcntl
import os
import sys
from ctypes import *

"""
Create 2 structs needed to encrypt/decrypt.
Not all structs are implemented yet.
You can find original c structs in cryptodev.h
"""


class crypt_op(Structure):

    _fields_ = [("ses",  c_uint32),
                ("op", c_uint16),
                ("flags", c_uint16),
                ("lend", c_uint32),
                ("src", POINTER(c_uint8)),
                ("dst", POINTER(c_uint8)),
                ("mac", POINTER(c_uint8)),
                ("iv", POINTER(c_uint8))]


class session_op(Structure):
    _fields_ = [("cipher",  c_uint32),
                ("mac",  c_uint32),
                ("keylen",  c_uint32),
                ("key",   POINTER(c_uint8)),
                ("mackeylen",  c_uint32),
                ("mackey",  POINTER(c_uint8)),
                ("ses", c_uint32)]

"""
Some defined variables from cryptodev.h needed
to encrypt/decrypt.
Only those needed exist here.
"""

CRYPTO_RIJNDAEL128_CBC = 11
CRYPTO_AES_CBC = CRYPTO_RIJNDAEL128_CBC
COP_ENCRYPT = 0
COP_DECRYPT = 1
CIOCGSESSION = ioctlh._IOWR(ord('c'), 102, sizeof(session_op))
CIOCCRYPT = ioctlh._IOWR(ord('c'), 104, sizeof(crypt_op))


# Define buffer size, key size and block size
BUFSIZE = 512
KEYSIZE = 16
BLOCKSIZE = 16

"""
This is the Data class.
No need to do write it like a c structure.
"""
class Data:
    def __init__(self, inp, iv, key):
        self.inpt = create_string_buffer(inp, BUFSIZE)
        self.iv = create_string_buffer(iv, BLOCKSIZE)
        self.key = create_string_buffer(key, KEYSIZE)
        self.encrypted = create_string_buffer("", BUFSIZE)
        self.decrypted = create_string_buffer("", BUFSIZE)

# Function to init session
def initsess(mydata, sess, fd):
    try:
        sess.cipher = c_uint32(CRYPTO_AES_CBC)
        sess.keylen = c_uint32(KEYSIZE)
        sess.key = cast(mydata.key, POINTER(c_uint8))
        fcntl.ioctl(fd, CIOCGSESSION, addressof(sess))
    except OSError, e:
        print str(e)
        sys.exit(1)


# Function to encrypt data
def encrypt(mydata, sess, cryp, fd):
    try:
        cryp.ses = c_uint32(sess.ses)
        cryp.lend = sizeof(mydata.inpt)
        cryp.src = cast(mydata.inpt, POINTER(c_uint8))
        cryp.dst = cast(mydata.encrypted, POINTER(c_uint8))
        cryp.iv = cast(mydata.iv, POINTER(c_uint8))
        cryp.op = c_uint16(COP_ENCRYPT)
        fcntl.ioctl(fd, CIOCCRYPT, addressof(cryp))
    except OSError, e:
        print str(e)
        sys.exit(1)

# Function to decrypt data
def decrypt(mydata, sess, cryp, fd):
    try:
        cryp.src = cast(mydata.encrypted, POINTER(c_uint8))
        cryp.dst = cast(mydata.decrypted, POINTER(c_uint8))
        cryp.op = c_uint16(COP_DECRYPT)
        fcntl.ioctl(fd, CIOCCRYPT, addressof(cryp))
    except OSError, e:
        print str(e)
        sys.exit(e)

# Function to print data in hex
def printMessage(msg1, msg2):
    hexMsg = ":".join("{:02x}".format(ord(c)) for c in msg2)
    print "*" * 100
    print msg1 + " (hex)\n%s\n" % hexMsg
    print "*" * 100

# Function to test encryption/decryption
def test(fd):
    inpt = "Hello cryptodev!"
    key = "qoelqielwidkrmqm"
    iv = "qoelqi1e2l3wimqm"

    mydata = Data(inpt, iv, key)
    sess = session_op()
    cryp = crypt_op()

    initsess(mydata, sess, fd)
    printMessage("Original data", mydata.inpt.value)
    encrypt(mydata, sess, cryp, fd)
    printMessage("Encrypted data", mydata.encrypted.value)
    decrypt(mydata, sess, cryp, fd)
    printMessage("Decrypted data", mydata.decrypted.value)
    if mydata.decrypted.value == mydata.inpt.value:
        print "Sucess!"
    else:
        print "Looser@"

# Main function
def main():
    try:
        fd = os.open("/dev/crypto", os.O_RDWR)
        test(fd)
        os.close(fd)
    except OSError, e:
        print str(type(e)) + str(e)
    except Exception, e:
        print str(type(e)) + str(e)

if __name__ == "__main__":
    main()
