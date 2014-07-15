python-bindings:
	python ctypesgen/ctypesgen.py  --insert-file crypto/fix.py crypto/cryptodev.h -o crypto/cryptodev.py
	cp crypto/cryptodev.py tests/