# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>

use strict;
use warnings;

our $PLANNED;
use Test;
BEGIN { $PLANNED = 16; plan tests => $PLANNED; }

# Load the functions in mailpw
do './mailpw';

my $ada_hash =
'$6$salt.to.taste$PQFilXtydPMPdJSK0JvL4IyVf1rJXKZIn557aCznpdjSupkcdmBQXroOfmcU2UkN5gj8wgG8tJ1Bvw5sx0rJm.';
my $brian_old_hash = '$1$I.amFrij$h8Orif34zr5liFE1ck9Js/';
my $margaret_hash =
'$6$PTvkXcXPHO9XWIeB$5071WNtHzcPz0ar6jThREZlT7Y3cAn4D84rzfu.TF.IanY9zxaQBhiC1KMaRVkEDq2NpQH6Y6SO59s9RoCyWN1';

my $passwd_in = <<"EOF";
ada:$ada_hash:1001:1001:Ada L:/home/ada:/bin/bash
brian:$brian_old_hash:1002:1002:Brian K:/home/brian:/bin/sh
margaret:$margaret_hash:1003:1003:Margaret H:/home/margaret:/bin/bash
EOF

my $user  = 'brian';
my $delim = ':';
my $brian_new_hash =
'$6$just.a.pinch$oBamM8jgbJcLY0b37N72jEgFkAahssOGbXPFDgXidFG3TYSBZvEDk4FhAxXF418fyxgyxUvrj00X5qHAxJ18Z.';

sub contains {
    my ( $haystack, $needle, $invert ) = @_;
    my $found = ( index( $haystack, $needle ) >= 0 )                 ? 1 : 0;
    my $ok    = ( ( $found && !$invert ) || ( !$found && $invert ) ) ? 1 : 0;
    if ($ok) {
        return $ok;
    }
    if ( !$found ) {
        printf STDERR "'$needle' not found in '$haystack'\n";
    }
    else {
        printf STDERR "unexepectedly found '$needle' in '$haystack'\n";
    }
    return 0;
}

sub not_contains {
    my ( $haystack, $needle ) = @_;

    my $invert = 1;
    return contains( $haystack, $needle, $invert );
}

my $ok = 0;

$ok += ok( contains( $passwd_in, "ada:$ada_hash:" ) );
$ok += ok( contains( $passwd_in, "brian:$brian_old_hash" ) );
$ok += ok( contains( $passwd_in, "margaret:$margaret_hash" ) );

$ok += ok( not_contains( $passwd_in, $brian_new_hash ) );

my $replaced = replace_hash( $passwd_in, $user, $delim, $brian_new_hash );

$ok += ok( contains( $replaced, "ada:$ada_hash:" ) );
$ok += ok( contains( $replaced, "brian:$brian_new_hash:" ) );
$ok += ok( contains( $replaced, "margaret:$margaret_hash" ) );

$ok += ok( not_contains( $replaced, $brian_old_hash ) );

# -----------------------------------------

$delim = '\s';
my $space_in = <<"EOF";
ada $ada_hash
brian $brian_old_hash
margaret $margaret_hash
EOF

$ok += ok( contains( $space_in, "ada $ada_hash" ) );
$ok += ok( contains( $space_in, "brian $brian_old_hash" ) );
$ok += ok( contains( $space_in, "margaret $margaret_hash" ) );

$ok += ok( not_contains( $space_in, $brian_new_hash ) );

$replaced = replace_hash( $space_in, $user, $delim, $brian_new_hash );

$ok += ok( contains( $replaced, "ada $ada_hash" ) );
$ok += ok( contains( $replaced, "brian $brian_new_hash" ) );
$ok += ok( contains( $replaced, "margaret $margaret_hash" ) );

$ok += ok( not_contains( $replaced, $brian_old_hash ) );

exit( $ok == $PLANNED ? 0 : 1 );
