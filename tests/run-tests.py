from os import system, path,listdir
from sys import executable
tests = ["async_cipher.py", "async_hmac.py", "async_speed.py",
			"cipher-aead-srtp.py", "cipher-aead.py", "cipher-gcm.py",
			"cipher.py", "cipher_comp.py", "fullspeed.py",
			"hash_comp.py", "hascrypt_speed.py", "hmac.py",
			"hmac_comp.py", "sha_speed.py", "speed.py"]

def main():
	try:
		files = [f for f in listdir('.') if path.isfile(f)]
		for f in set(files) & set(tests):
			print 40 * "="
			print "Running " + f
			print 40 * "="
			system(executable + " " + f)
			print ""
		print 40 * "="
	except Exception, e:
		print str(e)

if __name__ == "__main__":
	main()
