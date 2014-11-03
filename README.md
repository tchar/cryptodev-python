cryptodev-python
================

Project to create C bindings for cryptodev in Python.

The bindings are basically a Python module named cryptodev (under crypto).
The module contains two Python files: ioctl.py and cryptodev.py translated from ioctl.h and cryptodev.h respectively.
To use the module just import cryptodev (e.g. from cryptodev import *)
You can find examples/tests under tests. Those tests were originally written into C by the authors of cryptodev. The tests that exist this repository are basically a translation from C to Python.

You can find cryptodev at; https://githu.cbonliom/cryptodev-linux/cryptodev-linux/
