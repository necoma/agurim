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
	#echo $agurim_cmd -i $grad $fnames
	#$agurim_cmd -i $grad $fnames 
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
monthdir_names=`ls $loc|sed -e '/^[0-9]\{6\}$/!d'`
for monthdir in $monthdir_names; do
	_monthdir=$loc/$monthdir
	if [ ! -d $_monthdir ]; then
		echo "This directory($_monthdir) is required but does not exist!"
		exit
	fi
done

case $grad in
'day') 
	for monthdir in $monthdir_names; do
		daydir_names=`ls $loc/$monthdir|sed -e '/^[0-9]\{8\}$/!d'`
		for daydir in $daydir_names; do
			echo Now, reaggregating agurim files at $daydir
			cmd_gen 300 "$loc/$monthdir/$daydir/$daydir.*.agr" "$loc/$monthdir/$daydir/$daydir.agr"
		done
	done
	;;
'month')
	for monthdir in $monthdir_names; do
		#if [ $monthdir != "201402" ]; then
		#	continue	
		#fi
		echo Now, reaggregating agurim files at $monthdir 
		daydir_names=`ls $loc/$monthdir|sed -e '/^[0-9]\{8\}$/!d'`
		dayfiles=''
		for daydir in $daydir_names; do
			dayfile=$loc/$monthdir/$daydir/$daydir.agr
			if [ ! -e $dayfile ]; then
				echo "This file($dayfile) is required but does not exist!"
				exit
			fi
			dayfiles="$dayfiles $dayfile"
		done
		cmd_gen 7200 "$dayfiles" "$loc/$monthdir/$monthdir.agr"
	done
	;;

'year')
	prev_year=''
	for monthdir in $monthdir_names; do
		monthfile=$loc/$monthdir/$monthdir.agr
		year=`echo $monthdir| sed -e 's/\([0-9]\{4\}\).*/\1/'`
		if [ -z "$prev_year" ]; then
			prev_year=$year
		fi
		if [ $year != $prev_year ]; then
			cmd_gen 86400 "$monthfiles" "$loc/$prev_year.agr"
			prev_year=$year
			monthfiles=''
		fi
		if [ ! -e $monthfile ]; then
			echo "This file($monthfile) is required but does not exist!"
			exit
		fi
		monthfiles="$monthfiles $monthfile"
	done
	cmd_gen 86400 "$monthfiles" "$loc/$year.agr"
	echo $monthfiles
	;;
*)
	echo second argument is wrong. Try again!
	echo
	usage
	;;
esac
