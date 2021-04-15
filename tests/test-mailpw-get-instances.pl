# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>

use strict;
use warnings;

use File::Temp qw( tempdir tempfile );

use Test;
BEGIN { plan tests => 7 }

# Load the functions in mailpw
do './mailpw';

# create a temp dir for our tests
my $dir = tempdir( CLEANUP => 1 );

# trailing Xs are changed
my $conf_template = "test-mailpw-XXXXXX";

my ( $conf_fh, $conf_fname ) =
  tempfile( $conf_template, DIR => $dir, UNLINK => 0, SUFFIX => ".conf" );

my $foo_pw_fname = '/foo/dovecot/passwd';
my $foo_sp_fname = '/foo/opensmtpd/users';
my $bar_pw_fname = '/bar/dovecot/passwd';
my $bar_sp_fname = '/bar/opensmtpd/users';

print $conf_fh <<"EOF";
# The Foo Files
foo\tpasswd\t$foo_pw_fname
foo\tspace\t$foo_sp_fname

# The Bar Files
bar\tpasswd\t$bar_pw_fname
bar\tspace\t$bar_sp_fname
EOF
close($conf_fh);

my $instances = get_instances($conf_fname);

ok( scalar( keys %$instances ) == 2 );

ok( scalar( keys %{ $instances->{foo} } ) == 2 );
ok( $instances->{foo}->{$foo_pw_fname} eq "passwd" );
ok( $instances->{foo}->{$foo_sp_fname} eq "space" );

ok( scalar( keys %{ $instances->{bar} } ) == 2 );
ok( $instances->{bar}->{$bar_pw_fname} eq "passwd" );
ok( $instances->{bar}->{$bar_sp_fname} eq "space" );
