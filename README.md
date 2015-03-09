cryptodev-python
================

Acknowledgment
--------------
I want to thank Vangelis Koukis for motivating me into developing this project.

About
-----
This is a project to create C bindings for cryptodev in Python (v2.7) semi-automatically.
This branch provides a way to create the bindings dynamically using Python ctypesgen.
To generate the module run:
make python-bindings
Be careful not to delete the fix.py because this is not a fully automated way to create the bindings through cryptodev.h and ioctl.h
The bindings are basically a Python module named cryptodev (under crypto). The module contains two Python files: ioctl.py and cryptodev.py translated from ioctl.h and cryptodev.h respectively. To use the module just import cryptodev (e.g. from cryptodev import *) You can find examples/tests under tests. Those tests were originally written into C by the authors of cryptodev. The tests that exist this repository are basically a translation from C to Python.

How to build/use?
-----------------
To build this, fork the ctypesgen project, from mine repository or the developers repository (links provided below).  
Then assign to the variable CTYPESGEN, located in this project’s Makefile, the ctypesgen.py location.  
Type: ```make```  
Go into tests folder, where a cryptodev module folder was just created.  
To run the tests you can use the script run_tests.py like: ```python run_tests.py```  
Note that you must run the script using python 2.7 version, not 3.  
To clean the project type: ```make clean```  


cryptodev/ctypesgen
-------------------
You can find cryptodev at: https://github.com/cryptodev-linux/cryptodev-linux/  
You can find ctypesgen at: https://code.google.com/p/ctypesgen/  
or at my repository: https://github.com/tchar/ctypesgen/

ctypesgen and python 3 support
------------------------------
As for now there is a version of ctypesgen that generates python 3 compatible code:
https://code.google.com/p/ctypesgen/source/browse/branches/python-3/
Although, the code generated is supposed to be compatible with python 3, it seems that there are some conflicts.
For example, there is usage of the constant sys.maxint, which was removed in python 3, etc.
Because of this, I cannot (currently) support python 3 for cryptodev using ctypesgen.
In the future, I may supply a workaround or a fix for this issue.

Why not fully-automated way?
----------------------------

Due to a problem I have with ctypesgen, a fix.py (located under crypto) is needed. 
The file crypto/python-bindings-fix.py contains all the cryptodev.h definitions that depend on the following ioctl.h's definitions: _IOWR, _IOW, _IOR.
The reason for this is that ctypesgen cannot parse definitions like the following:
```C
#define THISDEFINE SOMEOTHERDEFINE(int) //This is like CRIOGET, but more simple as an example
```
At first it may look like that the problem occurs because cryptodev.h uses definitions from ioctl.h without including the header, but even if we include the header explicitly we get a warning (stating that ctypesgen cannot parse some lines) resulting in not including those definitions in the python output file.
Concluding, ctypesgen cannot parse a definition in which we use another definition that takes some types.
Note that something like the following works:
```C
#define SOMEOTHERDEFINE(x) sizeof(x) //This is basically _IOC_TYPECHECK definition of ioctl.h
#define THISDEFINE(x) SOMEOTHERDEFINE(x)
```
