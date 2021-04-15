# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>
# Copyright (C) 2021 Keith Reynolds <keithr@pwcrypt.keithr.com>

# $@ : target label
# $< : the first prerequisite after the colon
# $^ : all of the prerequisite files
# $* : wildcard matched part
# Target-specific Variable syntax:
# https://www.gnu.org/software/make/manual/html_node/Target_002dspecific.html
#
# patsubst : $(patsubst pattern,replacement,text)
#       https://www.gnu.org/software/make/manual/html_node/Text-Functions.html

PERL ?= perl

PWC_CFLAGS=-g -Wall -Wextra -Wpedantic -Werror
PWC_LDADD=-lcrypt

pwcrypt: pwcrypt.c
	$(CC) $(PWC_CFLAGS) $< -o $@ $(PWC_LDADD)

TEST_DEPS=pwcrypt.c tests/test-util.h tests/test-util.c
TEST_CFLAGS=-DPWCRYPT_TEST=1 -I. $(PWC_CFLAGS)

test-crypt-algo: tests/test-crypt-algo.c $(TEST_DEPS)
	$(CC) $(TEST_CFLAGS) $< -o $@ $(PWC_LDADD)

check-crypt-algo: test-crypt-algo
	./test-crypt-algo
	@echo "SUCCESS! ($@)"

test-getpass: tests/test-getpass.c $(TEST_DEPS)
	$(CC) $(TEST_CFLAGS) $< -o $@ $(PWC_LDADD)

check-getpass: test-getpass
	./test-getpass
	@echo "SUCCESS! ($@)"

test-is-valid-for-salt: tests/test-is-valid-for-salt.c $(TEST_DEPS)
	$(CC) $(TEST_CFLAGS) $< -o $@ $(PWC_LDADD)

check-is-valid-for-salt: test-is-valid-for-salt
	./test-is-valid-for-salt
	@echo "SUCCESS! ($@)"

check-mailpw-ensure-filename: tests/test-mailpw-ensure-filename.pl mailpw
	$(PERL) tests/test-mailpw-ensure-filename.pl
	@echo "SUCCESS! ($@)"

check-mailpw-get-instances: tests/test-mailpw-get-instances.pl mailpw
	$(PERL) tests/test-mailpw-get-instances.pl
	@echo "SUCCESS! ($@)"

check-mailpw-who-am-i: tests/test-mailpw-who-am-i.pl mailpw
	$(PERL) tests/test-mailpw-who-am-i.pl
	@echo "SUCCESS! ($@)"

check-mailpw-who-am-i-false-env: tests/test-mailpw-who-am-i.pl mailpw
	USER=foo $(PERL) tests/test-mailpw-who-am-i.pl $(USER)
	@echo "SUCCESS! ($@)"

check-mailpw-replace-hash: tests/test-mailpw-replace-hash.pl mailpw
	$(PERL) tests/test-mailpw-replace-hash.pl
	@echo "SUCCESS! ($@)"

check-mailpw-change-passwd: tests/test-mailpw-change-passwd.pl mailpw pwcrypt
	$(PERL) tests/test-mailpw-change-passwd.pl
	@echo "SUCCESS! ($@)"

check-unit: check-crypt-algo \
		check-getpass \
		check-is-valid-for-salt \
		check-mailpw-ensure-filename \
		check-mailpw-get-instances \
		check-mailpw-who-am-i \
		check-mailpw-who-am-i-false-env \
		check-mailpw-replace-hash \
		check-mailpw-change-passwd
	@echo "SUCCESS! ($@)"

check-acceptance-sha512: ./tests/check-sha512 tests/expect-no-confirm.sh \
		pwcrypt
	$(PERL) ./tests/check-sha512
	@echo "SUCCESS! ($@)"

check-acceptance-md5: ./tests/check-md5 tests/expect-confirm.sh pwcrypt
	$(PERL) ./tests/check-md5
	@echo "SUCCESS! ($@)"

# TODO:
# check-acceptance-mailpw: mailpw pwcrypt
#	mkdir -pv faux
#	cp -iv tests/faux-passwd faux/dovecot-passwd
#	cp -iv tests/faux-space faux/opensmtpd-users
#	sed -i -e "s/USER/$$USER/g" faux/*
#	# ./pwcrypt tests/faux-mailpw.conf
#	expect-mailpw tests/faux-mailpw.conf \
#		pinch.of.salt 'Ever expanding cirlcles of love!'

check-acceptance: check-acceptance-md5 check-acceptance-sha512
	@echo "SUCCESS! ($@)"

check: check-unit check-acceptance
	@echo "SUCCESS! ($@)"

# extracted from https://github.com/torvalds/linux/blob/master/scripts/Lindent
LINDENT=indent -npro -kr -i8 -ts8 -sob -l80 -ss -ncs -cp1 -il0
# see also: https://www.kernel.org/doc/Documentation/process/coding-style.rst
tidy-c:
	$(LINDENT) \
		-T FILE \
		-T size_t -T ssize_t \
		-T crypt_data \
		-T termios \
		tests/*.h tests/*.c \
		pwcrypt.c

PERL_SRC=mailpw \
	tests/check-md5 \
	tests/check-sha512 \
	tests/*.pl

tidy-perl:
	#TODO: replace for-loop with Makefile magic
	for FILE in $(PERL_SRC); do \
		$(PERL) -c $$FILE \
			&& perltidy $$FILE \
			&& mv $$FILE $$FILE~ \
			&& mv $$FILE.tdy $$FILE; \
	done

tidy: tidy-c tidy-perl

clean:
	rm -fv `cat .gitignore`
