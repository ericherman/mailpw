pwcrypt: pwcrypt.c
	$(CC) ./pwcrypt.c -o pwcrypt -lcrypt

clean:
	rm -fv pwcrypt
