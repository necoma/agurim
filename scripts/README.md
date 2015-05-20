# reaggregate.sh
========
A script for reaggregating aguri2 traffic summaries.

reaggregate.sh is used to re-aggregate traffic summaries created by
aguri2.
This script is supposed to be invoked by a cron job every hour.
The script re-aggregate day's summary with 5-minute resolution.
If the hour is 23 (11p.m.), the script also updates the monthly
summary with 2-hour resolution and the yearly summary with 24-hour
resolution.

If the '-t' option is not specified, it aggregates day's log using
the time: 1 hour before the current time.


## Usage

To re-aggregate today's dataset under a specified log directory:

	reaggregate.sh [-d logdir]

To copy today's data from a remote site and reaggregate under a
specified log directory:

	reaggregate.sh [-d logdir] [-r host:path] [-o owner]

To re-aggregate a specific day:

	reaggregate.sh [-d logdir] [-t yyyymmddHH]

  + `-d logdir`:
    Specify the log directory.  The re-aggregated files are created under
    this directory.
  
  + `-r host:path`:  
    Copy data from a remote site using rsync(1).  'host:path' is
    passed to rsync(1) as remote directory
    (e.g., 'host.example.com:/export/aguri2').

  + `-o owner`:  
    Specify the owner of new files when copying from a remote site.
    'owner' is passed to '--chown=${owner}' for rsync(1).

  + `-t yyyymmdd[HH]`:  
    Specify the day to re-aggregate.  If 'HH' is '23', agurify2.sh
    updates the monthly summary and the yearly summary.
    Otherwise, agurify2.sh updates only the daily summary.

## Examples

To run reaggregate.sh at minute 1 every hour,
set the following entry in the crontab.

	1 * * * * /script_path/reaggregate.sh -d /export/aguri2 2>&1

Similary, for copying the data from a remote host, and then, re-aggregate:

	1 * * * * /script_path/reaggregate.sh -r 'host.example.com:/export/aguri2' -o 'kjc:staff' -d /export/aguri2 2>&1

To update the daily summary on May 15, 2015:

	reaggregate.sh -d /export/aguri2 -t 20150515

Similarly, to update the daily summary along with the monthly summary
and yearly summary, add '23' hour to the time string.

	reaggregate.sh -d /export/aguri2 -t 2015051523


