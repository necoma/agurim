# agurim
========
agurim: agurim re-aggregation tool

agurim reads files in the Aguri format, perform re-aggregation, and
print the results to the standard output.  When multiple input files
are specified, the files should be passed in the chronological order.
If no file is specified, agurim reads the data from the standard
input for re-aggregation, but reading from the standard input is not
supported for the plotting mode as the plotting mode needs to read the
data twice.

# Install

	% cd src
	% make
	% sudo make install`

# Usage

	agurim [-dhpvDP] [other options] [files]
	    other options:
		[-f filter] [-i interval] [-m byte|packet]
		[-n nflows] [-s duration] [-t thresh]
		[-S starttime] [-E endtime]

  + `-d`:  
    Set the plotting output format to the text format.
  
  + `-f filter`:  
    Specify a flow filter.
    The filter format is 'src_addr[/plen] dst_addr[/plen]' for address,
    'proto:sport:dport' for protocol and ports.

  + `-h`: Display help information and exit.

  + `-i interval`:  
    Specify the aggregation interval in seconds.
    Default is 60 (60 seconds).

  + `-m byte|packet`:  
    Specify the aggregation criteria.  The value is either 'byte' or 'packet'.
    When this option is absent, both byte count and packet count are used,
    and a flow is aggregatated when both counts are under the threshold.

  + `-n nflows`:  
    Specify the number of flows for plotting.  Default is 7.

  + `-p`:  
    Set the plotting mode to output plot data.
    The plot output is in the JSON format by default.
    If `-d` is also specified, the output format is plain text.
    When `-p` is not specified, agurim is in the re-aggregation mode,
    and output re-aggregation results in the Aguri format in plain text.

  + `-s duration`:  
    Specify the aggregation duration in seconds.

  + `-t thresh`:  
    Specify the threshold value for aggregation.  The unit is 1%.
    Default is 1 (1%).

  + `-v`:
    Print extra debug messages.

  + `-D`:
    Disable protocol specific heuristics for aggregation.

  + `-E endtime`:  
    Specify the endtime in Unix time.

  + `-P`:  
    Use protocol and port for the main attribute, and adress for
    the sub-attribute.
    By default, the main attribute is addresses, and the sub-attribute
    is protocol and port.

  + `-S starttime`:  
    Specify the starttime in Unix time.

# Examples

To re-aggregate file1.agr and file2.agr with 1-hour interval:

	agurim -i 3600 file1.agr file2.agr

To make a plot data with 10-minute resolution from file.agr

	agurim -pd -i 600 file.agr

To specify the time period, you have to specify two among 'starttime',
'endtime' and 'duration'.

	agurim -i 3600 -d 86400 -S 1426172400 file.agr


