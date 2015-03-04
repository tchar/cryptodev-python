PYTHON=/usr/bin/python2
CTYPESGEN=$(CTYPESGEN_PATH)/ctypesgen.py

python-bindings: ioctl.py cryptodev.py

cryptodev.py:
	$(PYTHON) $(CTYPESGEN) --insert-file crypto/fix.py crypto/cryptodev.h -o crypto/cryptodev/cryptodev.py

ioctl.py:
	$(PYTHON) $(CTYPESGEN) /usr/include/linux/ioctl.h -o crypto/cryptodev/ioctl.py

clean:
	rm -f crypto/cryptodev/cryptodev.py
	rm -f crypto/cryptodev/ioctl.py
	rm -f crypto/cryptodev/*.pyc
