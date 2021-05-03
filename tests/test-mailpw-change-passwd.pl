# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>

use strict;
use warnings;

use File::Temp qw( tempdir tempfile );

our $PLANNED;
use Test;
BEGIN { $PLANNED = 44; plan tests => $PLANNED; }

# Load the functions in mailpw
do './mailpw';

sub file_contains {
    my ( $filename, $string ) = @_;

    open( my $fh, $filename ) or die("Could not open '$filename'");
    my $lines = 0;
    my $found = 0;
    while ( my $line = <$fh> ) {
        ++$lines;
        if ( index( $line, $string ) >= 0 ) {
            $found = 1;
            last;
        }
    }
    close($fh);
    return $found;
}

sub groups {
    my @groups = split( /\s/, `groups` );
    return wantarray ? @groups : \@groups;
}

sub get_secondary_group {
    my ($user) = @_;
    $user //= $ENV{USER};
    my ($user_group) = getgrnam($user);
    for my $group ( groups() ) {
        if ( ( $group ne $user_group ) && ( $group ne ':' ) ) {
            return $group;
        }
    }
    warn "no other group found for $user";
    return;
}

# create a temp dir for our tests
my $dir = tempdir( CLEANUP => 1 );

# trailing Xs are changed
my $conf_template = "test-mailpw-XXXXXX";
my $pw_tmpl       = "passwd-XXXXXX";
my $sp_tmpl       = "users-XXXXXX";

my ( $foo_pw_fh, $foo_pw_fname ) =
  tempfile( $pw_tmpl, DIR => $dir, UNLINK => 0 );
my ( $foo_sp_fh, $foo_sp_fname ) =
  tempfile( $sp_tmpl, DIR => $dir, UNLINK => 0 );
my ( $bar_pw_fh, $bar_pw_fname ) =
  tempfile( $pw_tmpl, DIR => $dir, UNLINK => 0 );
my ( $bar_sp_fh, $bar_sp_fname ) =
  tempfile( $sp_tmpl, DIR => $dir, UNLINK => 0 );

my $ada_hash =
'$6$salt.to.taste$PQFilXtydPMPdJSK0JvL4IyVf1rJXKZIn557aCznpdjSupkcdmBQXroOfmcU2UkN5gj8wgG8tJ1Bvw5sx0rJm.';
my $brian_oldhash = '$1$I.amFrij$h8Orif34zr5liFE1ck9Js/';
my $margaret_hash =
'$6$PTvkXcXPHO9XWIeB$5071WNtHzcPz0ar6jThREZlT7Y3cAn4D84rzfu.TF.IanY9zxaQBhiC1KMaRVkEDq2NpQH6Y6SO59s9RoCyWN1';

print $foo_pw_fh <<"EOF";
ada:$ada_hash:1001:1001:Ada L:/home/ada:/bin/bash
brian:$brian_oldhash:1002:1002:Brian K:/home/brian:/bin/sh
EOF
close($foo_pw_fh);

my $some_other_group = get_secondary_group();

my @args = ( "chgrp", $some_other_group, $foo_pw_fname );
system(@args) == 0 or die "system(@args) failed: $?";

@args = ( "chmod", "0640", $foo_pw_fname );
system(@args) == 0 or die "system(@args) failed: $?";

print $foo_sp_fh <<"EOF";
ada $ada_hash
brian $brian_oldhash
EOF
close($foo_sp_fh);

print $bar_pw_fh <<"EOF";
brian:$brian_oldhash:1002:1002:Brian K:/home/brian:/bin/sh
margaret:$margaret_hash:1003:1003:Margaret H:/home/margaret:/bin/bash
EOF
close($bar_pw_fh);

print $bar_sp_fh <<"EOF";
brian $brian_oldhash
margaret $margaret_hash
EOF
close($bar_sp_fh);

my ( $conf_fh, $conf_path ) =
  tempfile( $conf_template, DIR => $dir, UNLINK => 0, SUFFIX => ".conf" );

print $conf_fh <<"EOF";
# The Foo Files
foo\tpasswd\t$foo_pw_fname
foo\tspace\t$foo_sp_fname

# The Bar Files
bar\tpasswd\t$bar_pw_fname
bar\tspace\t$bar_sp_fname
EOF
close($conf_fh);

my $salt  = 'just.a.pinch';
my $newpw = 'Love is infinite, time is not.';
my $brian_newhash =
'$6$just.a.pinch$oBamM8jgbJcLY0b37N72jEgFkAahssOGbXPFDgXidFG3TYSBZvEDk4FhAxXF418fyxgyxUvrj00X5qHAxJ18Z.';

ok( file_contains( $foo_pw_fname,  "ada:$ada_hash:" ) );
ok( file_contains( $foo_pw_fname,  "brian:$brian_oldhash:" ) );
ok( !file_contains( $foo_pw_fname, $brian_newhash ) );
ok( !file_contains( $foo_pw_fname, "margaret" ) );
ok( !file_contains( $foo_pw_fname, $margaret_hash ) );

ok( file_contains( $foo_sp_fname,  "ada $ada_hash" ) );
ok( file_contains( $foo_sp_fname,  "brian $brian_oldhash" ) );
ok( !file_contains( $foo_sp_fname, $brian_newhash ) );
ok( !file_contains( $foo_sp_fname, "margaret" ) );
ok( !file_contains( $foo_sp_fname, $margaret_hash ) );

ok( !file_contains( $bar_pw_fname, "ada:" ) );
ok( !file_contains( $bar_pw_fname, $ada_hash ) );
ok( file_contains( $bar_pw_fname,  "brian:$brian_oldhash:" ) );
ok( !file_contains( $bar_pw_fname, $brian_newhash ) );
ok( file_contains( $bar_pw_fname,  "margaret:$margaret_hash:" ) );

ok( !file_contains( $bar_sp_fname, "ada" ) );
ok( !file_contains( $bar_sp_fname, $ada_hash ) );
ok( file_contains( $bar_sp_fname,  "brian $brian_oldhash" ) );
ok( !file_contains( $bar_sp_fname, $brian_newhash ) );
ok( file_contains( $bar_sp_fname,  "margaret $margaret_hash" ) );

my $outstr = '';
open( my $fakeout, '>', \$outstr ) or die "Can't open local string? $!";

my $pwcrypt_cmd = "tests/expect-no-confirm email sha512 $salt '$newpw'";
change_instance_passwds( $fakeout, 'brian', $conf_path, $pwcrypt_cmd );
close($fakeout);

ok( index( $outstr, "foo" ) >= 0 );
ok( index( $outstr, "bar" ) >= 0 );

ok( file_contains( $foo_pw_fname,  "ada:$ada_hash:" ) );
ok( file_contains( $foo_pw_fname,  "brian:$brian_newhash:" ) );
ok( !file_contains( $foo_pw_fname, $brian_oldhash ) );
ok( !file_contains( $foo_pw_fname, "margaret" ) );
ok( !file_contains( $foo_pw_fname, $margaret_hash ) );

ok( file_contains( $foo_sp_fname,  "ada $ada_hash" ) );
ok( file_contains( $foo_sp_fname,  "brian $brian_newhash" ) );
ok( !file_contains( $foo_sp_fname, $brian_oldhash ) );
ok( !file_contains( $foo_sp_fname, "margaret" ) );
ok( !file_contains( $foo_sp_fname, $margaret_hash ) );

ok( !file_contains( $bar_pw_fname, "ada:" ) );
ok( !file_contains( $bar_pw_fname, $ada_hash ) );
ok( file_contains( $bar_pw_fname,  "brian:$brian_newhash:" ) );
ok( !file_contains( $bar_pw_fname, $brian_oldhash ) );
ok( file_contains( $bar_pw_fname,  "margaret:$margaret_hash:" ) );

ok( !file_contains( $bar_sp_fname, "ada" ) );
ok( !file_contains( $bar_sp_fname, $ada_hash ) );
ok( file_contains( $bar_sp_fname,  "brian $brian_newhash" ) );
ok( !file_contains( $bar_sp_fname, $brian_oldhash ) );
ok( file_contains( $bar_sp_fname,  "margaret $margaret_hash" ) );

my ( undef, undef, $foo_pw_mode, undef, undef, $foo_pw_gid ) =
  stat($foo_pw_fname);
my $foo_pw_group = getgrgid($foo_pw_gid);

ok( sprintf( "%04o", $foo_pw_mode ), "10" . "0640" );

ok( $foo_pw_group, $some_other_group );
