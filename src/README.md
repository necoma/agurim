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

	agurim [-dhpvDFP] [other options] [files]
	    other options:
		[-f filter] [-i interval] [-m byte|packet]
		[-n nflows] [-s duration] [-t thresh] [-w file]
		[-S starttime] [-E endtime]

  + `-d`:  
    Set the plotting output format to the text format.
  
  + `-f filter`:  
    Specify a flow filter.
    The filter format is 'src_addr[/plen] dst_addr[/plen]' for address,
    'proto:sport:dport' for protocol and ports.

  + `-h`: Display help information and exit.

  + `-i interval`:  
    Specify the aggregation interval in seconds. Zero interval means
    the entire duration of the input.
    Default is 0.

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

  + `-w file`:
    Specify the output file name.  By default, the results are printed
    to stdout.

  + `-D`:
    Disable protocol specific heuristics for aggregation.

  + `-E endtime`:  
    Specify the endtime in Unix time.

  + `-F`:  
    Read binary aguri flow records, instead of text-based aguri2 output,
    from stdin.  This is for testing purposes.

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

========
# aguri3

aguri3: a new thread-based primary aggregation tools for agurim

aguri3 is the primary aggregation tool for agurim.
aguri3 employs pthread, one thread for input processing and another
for aggregation and output.
aguri3 can produce aggregated flow records using the pcap library, or
reading the aguri_flow records from the standard input.
To read NetFlow or sFlow, use "aguri2_xflow" under the subdirectory.

aguri3 reopens the output file when it receives a HUP signal, which can
be used for log-rotation.

# Usage

	aguri3 [-dhvD] [other options] [files]
	    other options:
		[-c count] [-f pcap_filter] [-i interval[,output_interval]]
		[-m byte|packet] [-p pid_file] [-r pcapfile] [-s pcap_snaplen]
		[-t thresh_percenrage] [-w outputfile]
		[-P rtprio] [-S starttime] [-E endtime]

  + `-c count`:  
    Exit after processing count packets.

  + `-d`: Enable debug outputs.
  
  + `-i interval[,output_interval]`:
    Specify the aggregation interval in seconds. Zero interval means
    the entire duration of the input.
    Default is 0.
    When output_interval is specified, aguri3 uses the 2-stage
    aggregation to reduce the CPU load and memory consumption.
    In the 2-stage aggregation, the input is aggregated every interval
    but the results are further aggregated to produce the output every
    output_interval.
  
  + `-f pcapfilters`:  
    Specify pcap filters.

  + `-h`: Display help information and exit.

  + `-i interval[,output_interval]`:
    Specify the aggregation interval in seconds. Zero interval means
    the entire duration of the input.
    Default is 0.

  + `-m byte|packet`:  
    Specify the aggregation criteria.  The value is either 'byte' or 'packet'.
    When this option is absent, both byte count and packet count are used,
    and a flow is aggregatated when both counts are under the threshold.

  + `-p pidfile`:  
    Write the process id to the pidfile.

  + `-r pcapfile`:  
    Read packets from pcapfile.

  + `-s duration`:  
    Specify the snaplen in bytes for pcap.

  + `-t thresh`:  
    Specify the threshold value for aggregation.  The unit is 1%.
    Default is 1 (1%).

  + `-v`:
    Print extra debug messages.

  + `-w file`:
    Direct output to the speficied file.  By default, output is
    directed to stdout.

  + `-D`:
    Disable protocol specific heuristics for aggregation.

  + `-E endtime`:  
    Specify the endtime in Unix time.

  + `-H max_hashentries`:  
    Specify the maximum size of the hash to hold the input flows.
    The default is 1000000 (1 million entries).

  + `-I interface`:  
    Listen on interface.

  + `-P rtprio`:  
    Set realtime priority (between 0 and 31, 0 is the highest).
    (Currently FreeBSD only)

  + `-S starttime`:  
    Specify the starttime in Unix time.

## Examples

To read from an interface and show output records:

	aguri3 -I <ifname>

To read from an interface and write the records to a file every 30
seconds:

	aguri3 -I <ifname> -i 30 -w <logfile>

To reduce the CPU load and memory consumption, use the 2-stage
aggregation.  For example, aggregate every 5 seconds but produce
output every 60 seconds:

	aguri3 -I <ifname> -i 5,60 -w <logfile>

To read a saved pcap file:

	aguri3 -r <pcapfile>

To read netflow data from port 2055, and produce aggregated flow
records every 60 seconds:

	aguri2_xflow -t netflow -p 2055 | aguri3 -i 60

Similary, to read sflow data from port 6343, and produce aggregated
flow records every 60 seconds: 

	aguri2_xflow -t sflow -p 6343 | aguri3 -i 60


