'''
Here we explicitly define all needed constants that appear
in cryptodevl.h. We do it this way because ctypesgen fail to parse
these constants from cryptodev. Makefile is used to build the whole
cryptodev module.
'''
# ioctl.py is constructed automatically by ctypesgen (Makefile)
from ioctl import _IOWR, _IOW, _IOR

CRIOGET         =	_IOWR(ord('c'), 101, __u32)
CIOCGSESSION    =	_IOWR(ord('c'), 102, struct_session_op)
CIOCFSESSION    =	_IOW(ord('c'), 103, __u32)
CIOCCRYPT       =	_IOWR(ord('c'), 104, struct_crypt_op)
CIOCKEY         =	_IOWR(ord('c'), 105, struct_crypt_kop)
CIOCASYMFEAT    =	_IOR(ord('c'), 106, __u32)
CIOCGSESSINFO 	=	_IOWR(ord('c'), 107, struct_session_info_op)

# to indicate that CRIOGET is not required in linux

CRIOGET_NOT_NEEDED	=	1

# additional ioctls for AEAD
CIOCAUTHCRYPT   =	_IOWR(ord('c'), 109, struct_crypt_auth_op)

'''
additional ioctls for asynchronous operation.
These are conditionally enabled since version 1.6.
'''
CIOCASYNCCRYPT    =	_IOW(ord('c'), 110, struct_crypt_op)
CIOCASYNCFETCH    =	_IOR(ord('c'), 111, struct_crypt_op)
