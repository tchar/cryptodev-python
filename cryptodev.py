from ioctl import _IOWR, _IOR, _IOW
from cryptodevh import *
from cryptodevh import __u32

CRIOGET      =   _IOWR(ord('c'), 101, __u32)
CIOCGSESSION  =  _IOWR(ord('c'), 102, struct_session_op)
CIOCFSESSION =  _IOW(ord('c'), 103, __u32)
CIOCCRYPT    =   _IOWR(ord('c'), 104, struct_crypt_op)
CIOCKEY       =  _IOWR(ord('c'), 105, struct_crypt_kop)
CIOCGSESSINFO = _IOWR(ord('c'), 107, struct_session_info_op)
CIOCAUTHCRYPT  = _IOWR(ord('c'), 109, struct_crypt_auth_op)
CIOCASYNCCRYPT  =  _IOW(ord('c'), 110, struct_crypt_op)
CIOCASYMFEAT  =  _IOR(ord('c'), 106, __u32)
CIOCASYNCFETCH  =  _IOR(ord('c'), 111, struct_crypt_op)
