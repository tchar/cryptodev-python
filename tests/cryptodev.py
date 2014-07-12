"""
First attempt to build a python binding to
communicate with cryptodev using ctypes.
ioctl contains useful functions in python
equivalent to ioctl.h, which can be found at:
http://lxr.free-electrons.com/source/include/uapi/asm-generic/ioctl.h
Copy of ioctl.py can be found here:
from http://code.activestate.com/recipes/578225-linux-ioctl-numbers-in-python/
ioctl.py created by Dima Tisnek

Author Tilemachos Charalampous <tilemachos.charalampous@gmail.com>
"""

# Import useful libs
from ctypes import c_uint16, c_uint32, c_uint8, c_char, sizeof, POINTER, Structure
import ioctl

"""
Defined constants from cryptodev.h needed
to encrypt/decrypt, etc.
"""
# API extensions for linux
CRYPTO_HMAC_MAX_KEY_LEN = 512
CRYPTO_CIPHER_MAX_KEY_LEN = 64

# All the supported algorithms

CRYPTO_DES_CBC = 1
CRYPTO_3DES_CBC = 2
CRYPTO_BLF_CBC = 3
CRYPTO_CAST_CBC = 4
CRYPTO_SKIPJACK_CBC = 5
CRYPTO_MD5_HMAC = 6
CRYPTO_SHA1_HMAC = 7
CRYPTO_RIPEMD160_HMAC = 8
CRYPTO_MD5_KPDK = 9
CRYPTO_SHA1_KPDK = 10
CRYPTO_RIJNDAEL128_CBC = 11
CRYPTO_AES_CBC = CRYPTO_RIJNDAEL128_CBC
CRYPTO_ARC4 = 12
CRYPTO_MD5 = 13
CRYPTO_SHA1 = 14
CRYPTO_DEFLATE_COMP = 15
CRYPTO_NULL = 16
CRYPTO_LZS_COMP = 17
CRYPTO_SHA2_256_HMAC = 18
CRYPTO_SHA2_384_HMAC = 19
CRYPTO_SHA2_512_HMAC = 20
CRYPTO_AES_CTR = 21
CRYPTO_AES_XTS = 22
CRYPTO_AES_ECB = 23
CRYPTO_AES_GCM = 50

CRYPTO_CAMELLIA_CBC = 101
CRYPTO_RIPEMD160 = 102
CRYPTO_SHA2_224 = 103
CRYPTO_SHA2_256 = 104
CRYPTO_SHA2_384 = 105
CRYPTO_SHA2_512 = 106
CRYPTO_SHA2_224_HMAC = 107
CRYPTO_ALGORITHM_ALL = 108 #Keep updated - see below

CRYPTO_ALGORITHM_MAX = (CRYPTO_ALGORITHM_ALL - 1)

#Values for ciphers
DES_BLOCK_LEN = 8
DES3_BLOCK_LEN = 8
RIJNDAEL128_BLOCK_LEN = 16
AES_BLOCK_LEN = RIJNDAEL128_BLOCK_LEN
CAMELLIA_BLOCK_LEN = 16
BLOWFISH_BLOCK_LEN = 8
SKIPJACK_BLOCK_LEN = 8
CAST128_BLOCK_LEN = 8

# the maximum of the above
EALG_MAX_BLOCK_LEN = 16

# Values for hashes/MAC
AALG_MAX_RESULT_LEN = 64

# maximum length of verbose alg names (depends on CRYPTO_MAX_ALG_NAME)
CRYPTODEV_MAX_ALG_NAME = 64

HASH_MAX_LEN = 64


"""
Create structs needed.
"""

# input of CIOCGSESSION
class session_op(Structure):
    # Specify either cipher or mac
    _fields_ = [("cipher",  c_uint32), # cryptodev_crypto_op_t
                ("mac",  c_uint32),  # cryptodev_crypto_op_t
                ("keylen",  c_uint32),
                ("key",   POINTER(c_uint8)),
                ("mackeylen",  c_uint32),
                ("mackey",  POINTER(c_uint8)),
                ("ses", c_uint32)]

class session_info_op(Structure):
    class alg_info(Structure):
        _fields_ = [("cra_name", c_char * CRYPTODEV_MAX_ALG_NAME),
                    ("cra_driver_name", c_char * CRYPTODEV_MAX_ALG_NAME)]
    _fields_ = [("ses", c_uint32),
                ("cipher_info", alg_info),
                ("has_info", alg_info),
                ("alignmask", c_uint16), # alignment constraints

                ("flags", c_uint32)]    # SIOP_FLAGS_*

"""
If this flag is set then this algorithm uses
a driver only available in kernel (software drivers,
or drivers based on instruction sets do not set this flag).

If multiple algorithms are involved (as in AEAD case), then
if one of them is kernel-driver-only this flag will be set.
"""

SIOP_FLAG_KERNEL_DRIVER_ONLY = 1
COP_ENCRYPT = 0
COP_DECRYPT = 1

# input of CIOCCRYPT
class crypt_op(Structure):
    _fields_ = [("ses",  c_uint32),
                ("op", c_uint16),
                ("flags", c_uint16),
                ("len", c_uint32),
                ("src", POINTER(c_uint8)),
                ("dst", POINTER(c_uint8)),
                ("mac", POINTER(c_uint8)),
                ("iv", POINTER(c_uint8))]

class crypt_auth_op(Structure):
    _fields_ = [("ses", c_uint32),
                ("op", c_uint16),
                ("flags", c_uint16),
                ("len", c_uint32),
                ("auth_len", c_uint32),
                ("auth_src", POINTER(c_uint8)),
                ("src", POINTER(c_uint8)),
                ("dst", POINTER(c_uint8)),
                ("tag", POINTER(c_uint8)),
                ("tag_len", c_uint32),
                ("iv", POINTER(c_uint8)),
                ("iv_len", c_uint32)]

"""
In plain AEAD mode the following are required:
flags   : 0
iv      : the initialization vector (12 bytes)
auth_len: the length of the data to be authenticated
auth_src: the data to be authenticated
len     : length of data to be encrypted
src     : the data to be encrypted
dst     : space to hold encrypted data. It must have
          at least a size of len + tag_size.
tag_size: the size of the desired authentication tag or zero to use
          the maximum tag output.

Note tag isn't being used because the Linux AEAD interface
copies the tag just after data.
"""

"""
In TLS mode (used for CBC ciphers that required padding)
the following are required:
flags   : COP_FLAG_AEAD_TLS_TYPE
iv      : the initialization vector
auth_len: the length of the data to be authenticated only
len     : length of data to be encrypted
auth_src: the data to be authenticated
src     : the data to be encrypted
dst     : space to hold encrypted data (preferably in-place). It must have
          at least a size of len + tag_size + blocksize.
tag_size: the size of the desired authentication tag or zero to use
          the default mac output.

Note that the padding used is the minimum padding.
"""

"""
In SRTP mode the following are required:
flags   : COP_FLAG_AEAD_SRTP_TYPE
iv      : the initialization vector
auth_len: the length of the data to be authenticated. This must
          include the SRTP header + SRTP payload (data to be encrypted) + rest

len     : length of data to be encrypted
auth_src: pointer the data to be authenticated. Should point at the same buffer as src.
src     : pointer to the data to be encrypted.
dst     : This is mandatory to be the same as src (in-place only).
tag_size: the size of the desired authentication tag or zero to use
          the default mac output.
tag     : Pointer to an address where the authentication tag will be copied.
"""

# struct crypt_op flags
COP_FLAG_NONE = (0 << 0) # totally no flag
COP_FLAG_UPDATE =(1 << 0) # multi-update hash mode
COP_FLAG_FINAL = (1 << 1) # multi-update final hash mode
COP_FLAG_WRITE_IV = (1 << 2) # update the IV during operation
COP_FLAG_NO_ZC = (1 << 3) # do not zero-copy
COP_FLAG_AEAD_TLS_TYPE =(1 << 4) # authenticate and encrypt using the
                                          # TLS protocol rules
COP_FLAG_AEAD_SRTP_TYPE = (1 << 5) # authenticate and encrypt using the
                                           # SRTP protocol rules
COP_FLAG_RESET = (1 << 6) # multi-update reset the state.
                                          # should be used in combination
                                          # with COP_FLAG_UPDATE

"""
Stuff for bignum arithmetic and public key
cryptography - not supported yet by linux
cryptodev.
"""

CRYPTO_ALG_FLAG_SUPPORTED = 1
CRYPTO_ALG_FLAG_RNG_ENABLE = 2
CRYPTO_ALG_FLAG_DSA_SHA = 4

class crparam(Structure):
    _fields_ = [("crp_p", POINTER(c_uint8)),
               ("crp_nbits", c_uint32)]

CRK_MAXPARAM = 8

class crypt_kop(Structure):
    _fields_ = [("crk_op", c_uint32),
                ("crk_status", c_uint32),
                ("crk_iparams", c_uint16),
                ("crk_opamars", c_uint16),
                ("crk_pad1", c_uint32),
                ("crk_param", crparam * CRK_MAXPARAM)]

CRK_MOD_EXP = 0
CRK_MOD_EXP_CRT = 1
CRK_DSA_SIGN = 2
CRK_DSA_VERIFY = 3
CRK_DH_COMPUTE_KEY = 4
CRK_ALGORITHM_ALL = 5

CRK_ALGORITHM_MAX = (CRK_ALGORITHM_ALL-1)

# features to be queried with CIOCASYMFEAT ioctl

CRF_MOD_EXP = (1 << CRK_MOD_EXP)
CRF_MOD_EXP_CRT = (1 << CRK_MOD_EXP_CRT)
CRF_DSA_SIGN = (1 << CRK_DSA_SIGN)
CRF_DSA_VERIFY = (1 << CRK_DSA_VERIFY)
CRF_DH_COMPUTE_KEY = (1 << CRK_DH_COMPUTE_KEY)


# ioctl's. Compatible with old linux cryptodev.h

CRIOGET = ioctl._IOWR(ord('c'), 101, sizeof(c_uint32))
CIOCGSESSION = ioctl._IOWR(ord('c'), 102, sizeof(session_op))
CIOCFSESSION = ioctl._IOW(ord('c'), 103, sizeof(c_uint32))
CIOCCRYPT = ioctl._IOWR(ord('c'), 104, sizeof(crypt_op))
CIOCKEY = ioctl._IOWR(ord('c'), 105, sizeof(crypt_kop))
CIOCASYMFEAT = ioctl._IOR(ord('c'), 106, sizeof(c_uint32))
CIOCGSESSINFO = ioctl._IOWR(ord('c'), 107, sizeof(session_info_op))

# to indicate that CRIOGET is not required in linux

CRIOGET_NOT_NEEDED = 1

# additional ioctls for AEAD
CIOCAUTHCRYPT = ioctl._IOWR(ord('c'), 109, sizeof(crypt_auth_op))

# additional ioctls for asynchronous operation.
# These are conditionally enabled since version 1.6.

CIOCASYNCCRYPT = ioctl._IOW(ord('c'), 110, sizeof(crypt_op))
CIOCASYNCFETCH = ioctl._IOR(ord('c'), 111, sizeof(crypt_op))
