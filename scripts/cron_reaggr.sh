#!/bin/bash

# XXX change agurim_cmd path if needed
agurim_cmd='../src/agurim'

if [ ! -e $agruim_cmd ]; then
	echo 'Check agurim command path embedded in this script.'
	exit
fi

usage () {
	echo usage
	echo \# bash $0 \<dir location\> \<granularity \(day/month\)\>
	echo
	exit
}

cmd_gen () {
	local grad=$1
	local fnames=$2
	local out=$3
	$agurim_cmd -i $grad $fnames > $out
}
if [ $# -lt 2 ];then
	usage
fi

# input arguments
loc=$1
grad=$2

# check the existence of the targeting directory
if [ ! -d $loc ]; then
	echo "Directory $loc does not exist!"
	echo "Try again:"
	usage
fi

#
# Granularity Guideline
# ------------------------------------------
# | 5-minute   aggregation | 30 seconds    |
# | daily   re-aggregation | 300 seconds   |
# | monthly re-aggregation | 86400 seconds |
# ------------------------------------------
#
month=`date +%Y%m`
day=`date +%Y%m%d`

monthdir=$loc/$month
if [ ! -d $monthdir ]; then
	echo "This directory($monthdir) is required but does not exist!"
	exit
fi
daydir=$loc/$month/$day
if [ ! -d $daydir ]; then
	echo "This directory($daydir) is required but does not exist!"
	exit
fi

case $grad in
'day') 
	cmd_gen 300 "$loc/$month/$day/$day.*.agr" "$loc/$month/$day/$day.agr"
	;;
'month')
	date=`date +%d`
	for i in $(seq 1 $date); do
		if [ $i -lt 10 ]; then
			dayfile=$monthdir/${month}0$i/${month}0$i.agr
		else
			dayfile=$monthdir/${month}0$i/${month}$i.agr
		fi
		if [ ! -d $dayfile ]; then
			echo "This file($dayfile) is required but does not exist!"
			exit
		fi
		dayfiles="$dayfiles $dayfile"
	done
	cmd_gen 86400 "$dayfiles" "$monthdir/$month.agr"
	;;
*)
	echo second argument is wrong. Try again!
	echo
	usage
	;;
esac
