# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>

use strict;
use warnings;

# Load the functions in mailpw
do './mailpw';

# @ARGV is similar to C's argv, except that the @ARGV of Perl does
# not contain the name of the program (that is the $0 variable).
exit( mailpw(@ARGV) );
