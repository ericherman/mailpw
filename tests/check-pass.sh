#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>

#set -x
set -e

while getopts ":f:u:t:nie" opt
do
	case $opt in
	f)
		SHADOW_FILE="$OPTARG"
		;;
	u)
		SHADOW_USER="$OPTARG"
		;;
	t)
		PWCRYPT_TYPE="--type=$OPTARG"
		;;
	n)
		PW_NO_CONFIRM="--no-confirm"
		;;
	i)
		PW_STDIN="--use-stdin"
		echo "" >&2
		echo "WARN: $PW_STDIN may not work" >&2
		echo "" >&2
		;;
	e)
		PW_ECHO_PASSWD="--echo-password"
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
# echo "PW='$PW'"
ALGO=`echo "$PW" | cut -d'$' -f2`
# echo "ALGO='$ALGO'"
SALT=`echo "$PW" | cut -d'$' -f3`
# echo "SALT='$SALT'"
GUESS=`$PWCRYPT $PWCRYPT_TYPE $PW_NO_CONFIRM $PW_STDIN $PW_ECHO_PASSWD \
	--algorithm=$ALGO --salt="$SALT"`
# echo "GUESS='$GUESS'"
if [ "$GUESS" = "$PW" ]
then
	echo OK
else
	echo BAD
	exit 1
fi
