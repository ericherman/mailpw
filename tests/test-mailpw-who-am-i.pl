# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>

use strict;
use warnings;

our $PLANNED;
use Test;
BEGIN { $PLANNED = 1; plan tests => $PLANNED }

# Load the functions in mailpw
do './mailpw';

# get the expected answer
my $expected = $ARGV[0];
$expected ||= $ENV{USER};

my $who = who_am_i();

my $ok = 0;

$ok += ok( $who, $expected );

exit( $ok == $PLANNED ? 0 : 1 );
