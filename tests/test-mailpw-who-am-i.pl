# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>

use strict;
use warnings;

use Test;
BEGIN { plan tests => 1 }

# Load the functions in mailpw
# (There is probably a better way to do this)
open my $fh, '<', './mailpw' or die "Can't open file $!";
my $mailpw = do { local $/; <$fh> };
close $fh;
eval $mailpw;

# get the expected answer
my $expected = $ARGV[0];
$expected ||= $ENV{USER};

my $who = who_am_i();

ok( $who eq $expected );
