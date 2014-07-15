python-bindings: cryptodev.py
	cp crypto/cryptodev.py tests/

cryptodev.py:
	python ctypesgen/ctypesgen.py  --insert-file crypto/fix.py crypto/cryptodev.h -o crypto/cryptodev.py

clean:
	rm -f crypto/cryptodev.py*
	rm -f tests/cryptodev.py*