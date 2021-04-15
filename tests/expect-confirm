#!/usr/bin/expect
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>
# Copyright (C) 2021 Keith Reynolds <keithr@pwcrypt.keithr.com>
set type [lindex $argv 0]
set algo [lindex $argv 1]
set salt [lindex $argv 2]
set pass [lindex $argv 3]
spawn ./pwcrypt --type=$type --algorithm=$algo --salt=$salt
expect "passphrase: "
send -- "$pass\r"
expect "passphrase: "
send -- "$pass\r"
expect eof
