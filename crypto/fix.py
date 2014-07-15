#!/usr/bin/python2
# Got it from http://code.activestate.com/recipes/578225-linux-ioctl-numbers-in-python/
# Created by Dima Tisnek

"""
Linux ioctl numbers made easy

size can be an integer or format string compatible with struct module

for example include/linux/watchdog.h:

#define WATCHDOG_IOCTL_BASE 'W'

struct watchdog_info {
__u32 options; /* Options the card/driver supports */
__u32 firmware_version; /* Firmware version of the card */
__u8 identity[32]; /* Identity of the board */
};

#define WDIOC_GETSUPPORT _IOR(WATCHDOG_IOCTL_BASE, 0, struct watchdog_info)

becomes:

WDIOC_GETSUPPORT = _IOR(ord('W'), 0, "=II32s")


"""
import struct
from ctypes import sizeof
# constant for linux portability
_IOC_NRBITS = 8
_IOC_TYPEBITS = 8

# architecture specific
_IOC_SIZEBITS = 14
_IOC_DIRBITS = 2

_IOC_NRMASK = (1 << _IOC_NRBITS) - 1
_IOC_TYPEMASK = (1 << _IOC_TYPEBITS) - 1
_IOC_SIZEMASK = (1 << _IOC_SIZEBITS) - 1
_IOC_DIRMASK = (1 << _IOC_DIRBITS) - 1

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2


def _IOC(dir, type, nr, size):
    if isinstance(size, str) or isinstance(size, unicode):
        size = struct.calcsize(size)
    return dir << _IOC_DIRSHIFT | \
           type << _IOC_TYPESHIFT | \
           nr << _IOC_NRSHIFT | \
           size << _IOC_SIZESHIFT


def _IO(type, nr): return _IOC(_IOC_NONE, type, nr, 0)
def _IOR(type, nr, size): return _IOC(_IOC_READ, type, nr, sizeof(size))
def _IOW(type, nr, size): return _IOC(_IOC_WRITE, type, nr, sizeof(size))
def _IOWR(type, nr, size): return _IOC(_IOC_READ | _IOC_WRITE, type, nr, sizeof(size))

# ioctl's. Compatible with old linux cryptodev.h

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