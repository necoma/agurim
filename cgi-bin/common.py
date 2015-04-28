import sys
import os.path
import os
import fnmatch
import json
import cgi 
import time
import datetime

YEAR = 31536000
MONTH = 2592000
DAY = 86400
DURATION = DAY	# default duration is 1 day

#
# naming for agurim log
#
# every 1 day  => YYYY.agr
# every 1 hour => YYYYMM.agr
# every 10 min => YYYYMMDD.agr
#
def combine_fnames(start, end, path):
        duration = end - start
	if duration >= MONTH*4:
		ret = combine_yearly_files(start, end, path)
	elif duration >= DAY*7:
		ret = combine_monthly_files(start, end, path)
	elif duration >= DAY:
		ret = combine_daily_files(start, end, path)
	else:
		ret = combine_fine_grain_files(start, end, path)
	return ret

def combine_yearly_files(start, end, path, fmt='%Y', grad=YEAR, files=''):
	while start < end + grad:
		start_str = datetime.datetime.fromtimestamp(start).strftime(fmt)
		fname = "%s.agr" % start_str
    		if os.path.exists(os.path.join(path, fname)) == True:
			files += " %s" % fname
		start += grad
	return files

def last_day_of_month(date):
	if date.month == 12: 
		return 31
	return (date.replace(month=date.month+1, day=1) - datetime.timedelta(days=1)).day

def combine_monthly_files(start, end, path, fmt='%Y%m', files=''):
	grad = DAY  # XXX
        # convert start to the first day of the month
        monthstart = datetime.datetime.fromtimestamp(start).replace(day=1)
        start = time.mktime(monthstart.timetuple())
	while start < end + grad:
		start_str = datetime.datetime.fromtimestamp(start).strftime(fmt)
		fname = "%s.agr" % os.path.join(start_str, start_str)
    		if os.path.exists(os.path.join(path, fname)) == True:
			files += " %s" % fname
		grad = last_day_of_month(datetime.datetime.fromtimestamp(start)) * DAY
		start += grad
	return files

def combine_daily_files(start, end, path, fmt='%Y%m%d', grad=DAY, subfmt='%Y%m', files=''):
	while start < end + grad:
		start_str = datetime.datetime.fromtimestamp(start).strftime(fmt)
		subdir_str = datetime.datetime.fromtimestamp(start).strftime(subfmt)
		fname = "%s.agr" % os.path.join(subdir_str, start_str, start_str)
    		if os.path.exists(os.path.join(path, fname)):
			files += " %s" % fname
                start += grad
	return files

def combine_fine_grain_files(start, end, path, fmt='%Y%m%d.%H', grad=3600, subfmt='%Y%m', subfmt2='%Y%m%d', files=''):
	while start < end + grad:
		start_str = datetime.datetime.fromtimestamp(start).strftime(fmt)
		subdir_str = datetime.datetime.fromtimestamp(start).strftime(subfmt)
		subdir_str2 = datetime.datetime.fromtimestamp(start).strftime(subfmt2)
		subdir_str3 = os.path.join(subdir_str, subdir_str2)
		for fname in sorted(os.listdir(os.path.join(path, subdir_str3))):
			if fnmatch.fnmatchcase(fname, '%s*.agr' % start_str):
				files += " %s/%s" % (subdir_str3, fname)
		start += grad
	return files

def get_fnames(path, duration, start_time=0, end_time=0):
        # compute start and end:
	if start_time != 0 and end_time != 0:
        	ts1 = start_time
                ts2 = end_time
	else:
                if duration == 0:
                        duration = DURATION
                if start_time != 0:
                        ts1 = start_time
                        ts2 = ts1 + duration
                elif end_time != 0:
                        ts2 = end_time
                        ts1 = ts2 - duration
                else:
                        now = datetime.datetime.now()
                        now_ts = time.mktime(now.timetuple())
                        ts2 = now_ts
                        ts1 = ts2 - duration
        # sys.stderr.write('get_fname: duration:%d start:%d end:%d ts1:%d ts2:%d' % (duration, start_time, end_time, ts1, ts2))

        res = combine_fnames(ts1, ts2, path)
	return (res, int(ts1), int(ts2))

def generate_cmdargs(criteria, interval, threshold, nflows, duration, start_time, end_time, filter, outfmt, view, files):
	args = ''
	if outfmt == 'json':
		args += ' -p'
	if outfmt == 'file':
		args += ' -d'
	
	if criteria:
		args += ' -m %s' % criteria
	if interval:
		args += ' -i %s' % int(interval)
	if threshold:
		args += ' -t %s' % int(threshold)
	if nflows:
		args += ' -n %s' % int(nflows)
	if duration:
		args += ' -s %s' % int(duration)
	if start_time:
		args += ' -S %s' % int(start_time)
	if end_time:
		args += ' -E %s' % int(end_time)
	if filter:
		args += ' -f "%s"' % filter
	if view and view == 'proto':
		args += ' -P'
	if files:
		args += ' %s' % files
	return args
