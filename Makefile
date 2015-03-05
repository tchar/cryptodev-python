PYTHON=/usr/bin/python2
CTYPESGEN=$(CTYPESGEN_PATH)/ctypesgen.py
PYTHON_BIND_FIX = crypto/python-bindings-fix.py

python-bindings:
	$(PYTHON) $(CTYPESGEN) --include-symbols="(_IOW|_IOWR|_IOR)" --include=sys/ioctl.h  --insert-file $(PYTHON_BIND_FIX) crypto/cryptodev.h -o crypto/cryptodev.py


clean:
	rm -f crypto/cryptodev.py
	rm -f crypto/*.pyc
