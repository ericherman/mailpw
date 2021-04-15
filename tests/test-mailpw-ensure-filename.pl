# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>

use strict;
use warnings;

use Test;
BEGIN { plan tests => 6 }

# Load the functions in mailpw
do './mailpw';

my $fname = '/my/path';
ok( ensure_filename($fname) eq $fname );

ok( length( default_config_filename() ) > 0 );

ok( ensure_filename() eq default_config_filename() );
ok( ensure_filename("") eq default_config_filename() );
