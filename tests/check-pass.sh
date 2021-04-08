#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>

# set -x
set -e

while getopts ":f:u:" opt
do
        case $opt in
        f)
                SHADOW_FILE="$OPTARG"
                ;;
        u)
                SHADOW_USER="$OPTARG"
                ;;
        \?)
                echo "Unknown Option: -$OPTARG" >&2
                exit 1
                ;;
        :)
                echo "Option -$OPTARG requires an argument" >&2
                exit 1
                ;;
        esac
done

if [ "_${SHADOW_FILE}_" == "__" ]
then
        SHADOW_FILE=$1
fi
if [ "_${SHADOW_FILE}_" == "__" ]
then
        SHADOW_FILE=/etc/shadow
fi
SHADOW_FILE=`readlink -vf "${SHADOW_FILE}"`
if [[ ! -e $SHADOW_FILE ]]
then
	echo "$SHADOW_FILE does not exist"
	exit 1
fi

if [ "_${SHADOW_USER}_" == "__" ]
then
        SHADOW_USER=$2
fi
if [ "_${SHADOW_USER}_" == "__" ]
then
        SHADOW_USER=$USER
fi

echo "reading '$SHADOW_FILE' for '$USER'"

if [[ -r $SHADOW_FILE ]]
then
	SUDO=''
	echo "(sudo not required)"
else
	SUDO='sudo'
	echo "(sudo required)"
fi

if [[ -e './pwcrypt' ]]
then
	PWCRYPT=./pwcrypt
elif [[ -e '../pwcrypt' ]]
then
	PWCRYPT=../pwcrypt
else
	PWCRYPT=pwcrypt
fi

PW=`$SUDO grep $SHADOW_USER "$SHADOW_FILE" | cut -f2 -d':'`
ALGO=`echo "$PW" | cut -d'$' -f2`
SALT=`echo "$PW" | cut -d'$' -f3`
GUESS=`$PWCRYPT --algorithm=$ALGO --salt="$SALT"`
if [ "$GUESS" = "$PW" ]
then
	echo OK
else
	echo BAD
	exit 1
fi
