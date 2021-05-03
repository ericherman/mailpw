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

my $ok = 0;

$ok += ok( index( $passwd_in, "ada:$ada_hash:" ) >= 0 );
$ok += ok( index( $passwd_in, "brian:$brian_old_hash" ) >= 0 );
$ok += ok( index( $passwd_in, "margaret:$margaret_hash" ) >= 0 );

$ok += ok( index( $passwd_in, $brian_new_hash ) < 0 );

my $replaced = replace_hash( $passwd_in, $user, $delim, $brian_new_hash );

$ok += ok( index( $replaced, "ada:$ada_hash:" ) >= 0 );
$ok += ok( index( $replaced, "brian:$brian_new_hash:" ) >= 0 );
$ok += ok( index( $replaced, "margaret:$margaret_hash" ) >= 0 );

$ok += ok( index( $replaced, $brian_old_hash ) < 0 );

# -----------------------------------------

$delim = '\s';
my $space_in = <<"EOF";
ada $ada_hash
brian $brian_old_hash
margaret $margaret_hash
EOF

$ok += ok( index( $space_in, "ada $ada_hash" ) >= 0 );
$ok += ok( index( $space_in, "brian $brian_old_hash" ) >= 0 );
$ok += ok( index( $space_in, "margaret $margaret_hash" ) >= 0 );

$ok += ok( index( $space_in, $brian_new_hash ) < 0 );

$replaced = replace_hash( $space_in, $user, $delim, $brian_new_hash );

$ok += ok( index( $replaced, "ada $ada_hash" ) >= 0 );
$ok += ok( index( $replaced, "brian $brian_new_hash" ) >= 0 );
$ok += ok( index( $replaced, "margaret $margaret_hash" ) >= 0 );

$ok += ok( index( $replaced, $brian_old_hash ) < 0 );

exit( $ok == $PLANNED ? 0 : 1 );
