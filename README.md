cryptodev-python
================
Project to create C bindings for cryptodev in Python semi-automatically.

This branch provides a way to create the bindings dynamically using Python ctypesgen.
To generate the module run:
make python-bindings
Be careful not to delete the fix.py because this is not a fully automated way to create the bindings through cryptodev.h and ioctl.h

The bindings are basically a Python module named cryptodev (under crypto). The module contains two Python files: ioctl.py and cryptodev.py translated from ioctl.h and cryptodev.h respectively. To use the module just import cryptodev (e.g. from cryptodev import *) You can find examples/tests under tests. Those tests were originally written into C by the authors of cryptodev. The tests that exist this repository are basically a translation from C to Python.

You can find cryptodev at: https://github.com/cryptodev-linux/cryptodev-linux/  
You can find ctypesgen at: https://code.google.com/p/ctypesgen/

Why not fully-automated way?
----------------------------

Due to a bug in ctypesgen a fix.py (located under crypto) is needed. 
The file crypto/fix.py contains all the cryptodev.h definitions that depend on the following ioctl.h's definitions: _IOWR, _IOW, _IOR.
The reason for this is that ctypesgen cannot parse definitions like the following:
```C
#define THISDEFINE SOMEOTHERDEFINE(int) //This is like CRIOGET, but more simple as an example
```
At first it may look like that the problem occurs because cryptodev.h uses definitions from ioctl.h without including the header, but even if we include the header explicitly we get a warning (stating that ctypesgen cannot parse some lines) resulting in not including those definitions in the python output file.
Concluding ctypesgen cannot parse a definition in which we use another definition that takes some types.
Note that something like the following works:
```C
#define SOMEOTHERDEFINE(x) sizeof(x) //This is basically _IOC_TYPECHECK definition of ioctl.h
#define THISDEFINE(x) SOMEOTHERDEFINE(x) //This is like CRIOGET, but more simple as an example
```
