pwcrypt: pwcrypt.c
	$(CC) ./pwcrypt.c -o pwcrypt -lcrypt

# extracted from https://github.com/torvalds/linux/blob/master/scripts/Lindent
LINDENT=indent -npro -kr -i8 -ts8 -sob -l80 -ss -ncs -cp1 -il0
# see also: https://www.kernel.org/doc/Documentation/process/coding-style.rst
tidy:
	$(LINDENT) \
		-T FILE \
		-T size_t -T ssize_t \
		-T crypt_data \
		-T termios \
		pwcrypt.c

clean:
	rm -fv `cat .gitignore`
