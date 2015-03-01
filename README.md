cryptodev-python
================

Acknowledgment
--------------
I want to thank Vangelis Koukis for motivating me into developing this project.

About
-----
This is a project to create C bindings for cryptodev in Python.  
The bindings are basically a Python module named cryptodev (under crypto).  
The module contains two Python files: ioctl.py and cryptodev.py translated from ioctl.h and cryptodev.h respectively.  
To use the module just import cryptodev (e.g. from cryptodev import *).  
You can find examples/tests under tests folder. Those tests were originally written into C by the authors of cryptodev. The tests that exist in this repository are basically a translation from C to Python.

How to run the tests?
---------------------
You need the cryptodev module installed (link provided below).  
Navigate into the tests folder and run the script run_tests.py as:  
```python run_tests.py```.  
Note that you must run the script using python 2.7 version and above (now supporting python 3).

cryptodev
---------
You can find cryptodev at: https://github.com/cryptodev-linux/cryptodev-linux/
