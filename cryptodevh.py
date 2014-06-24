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
