#!/usr/bin/expect
set username [lindex $argv 0]
set passphrase [lindex $argv 1]
spawn tests/check-pass.sh -n \
	-f tests/faux-shadow \
	-u $username \
	-t fake-shadow
expect "input fake-shadow passphrase: "
send -- "$passphrase\r"
expect {
	"OK" exp_continue
	"BAD" exit 1
}
