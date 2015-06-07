#!/bin/sh
#
# usage:
#  reaggregate.sh [-d logdir] # for re-aggregation by cron job
#  reaggregate.sh [-d logdir] [-r host:path] [-o owner] # rsync/re-agg by cron
#  reaggregate.sh [-d logdir] [-t YYYYmmddHH] # re-aggregate for a given day
#

logdir="/work/aguri2"	# log directory
agurim="/usr/local/bin/agurim"	# agurim program
timestamp=""	# timestamp in "yyyymmddHH".  specify 23 for HH to
		# update monthly and yearly files

# for remote copy
rsync="/usr/local/bin/rsync"	# rsync program
remote=""			# remote dir e.g., "agurim.example.com:/logdir"
owner=""			# owner of logs e.g., "kjc:staff"
verbose=false

# process arguments
while getopts "d:o:p:r:s:t:v" opt; do
    case $opt in
	"d" ) logdir="$OPTARG" ;;
	"o" ) owner="$OPTARG" ;;
	"r" ) remote="$OPTARG" ;;
	"t" ) timestamp="$OPTARG" ;;
	"v" ) verbose=true ;;
	* ) echo "Usage: reaggregate.sh [-d logdir] [-r host:path] [-o owner] [-t yyyymmddHH]" 1>&2
	    exit 1 ;;
    esac
done


if [ "X${timestamp}" = "X" ]; then
    # if timestamp is not specified, use 'current time' - '1 hour'
    osname=`uname -s`
    case $osname in
	Linux) timestamp=$(/bin/date -d '1 hour ago' '+%Y %m %d %H') ;;
	*)     timestamp=$(/bin/date -v -1H '+%Y %m %d %H') ;;
    esac
    set -- $timestamp
    year=$1
    month=$2
    day=$3
    hour=$4
    if [ "${min}" = "00" ]; then
	# if zero minute, add extra wait for the primary aggregatin to finish
	sleep 20
    fi
else
    # extract date components from the time string
    year=$(echo $timestamp | awk '{print substr($0, 1, 4)}')
    month=$(echo $timestamp | awk '{print substr($0, 5, 2)}')
    day=$(echo $timestamp | awk '{print substr($0, 7, 2)}')
    hour=$(echo $timestamp | awk '{print substr($0, 9, 2)}')
fi

if [ "X${remote}" != "X" ]; then
    # if remote host is specified, rsync files under the day directory
    optown=""
    if [ "X${owner}" != "X" ]; then
	optown="--chown=${owner}"
    fi
    mkdir -p "${logdir}/${year}${month}"
    mkdir -p "${logdir}/${year}${month}/${year}${month}${day}"
    cmd="${rsync} -Cax ${optown} ${remote}/${year}${month}/${year}${month}${day}/ ${logdir}/${year}${month}/${year}${month}${day}"
    ${verbose} && eval echo "exec cmd: ${cmd}" 1>&2
    eval "${cmd}"
else
    # sanity check
    if [ ! -d "${logdir}/${year}${month}/${year}${month}${day}" ]; then
	echo "log dir: ${logdir} does not exist" 1>&2
	exit 1
    fi
fi

#
# update daily file (and monthly and yearly files)
#
cd "${logdir}/${year}${month}/${year}${month}${day}" || exit $?
dstfile="${year}${month}${day}.agr"
res="300" # time resolution (5 minutes)
files="${year}${month}${day}.??????.agr"

cmd="${agurim} -i ${res} ${files} > ${dstfile}"
${verbose} && echo "exec cmd: ${cmd}" 1>&2
eval "${cmd}"

# if this is 11pm, update monthly and yearly files
if [ "$hour" = "23" ]; then
    res="7200" # time resolution (2 hours)
    cd "${logdir}/${year}${month}"
    dstfile="${year}${month}.agr"
    files="${year}${month}??/${year}${month}??.agr"
    cmd="${agurim} -i ${res} ${files} > ${dstfile}"
    ${verbose} && echo "exec cmd: ${cmd}" 1>&2
    eval "${cmd}"

    # also update yearly data
    res="86400" # time resolution (24 hours)
    cd "${logdir}"
    dstfile="${year}.agr"
    files="${year}??/${year}??.agr"
    cmd="${agurim} -i ${res} ${files} > ${dstfile}"
    ${verbose} && echo "exec cmd: ${cmd}" 1>&2
    eval "${cmd}"
fi

exit 0
