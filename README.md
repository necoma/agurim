# agurim
========
agurim: a multi-dimensional flow aggregation tool

This source tree contains the tools to build the agurim web server,
including the source code of the re-aggregation engine and web
user interface.

The primary aggregation tools for agurim can be found at
https://github.com/necoma/aguri2/

# Layout

	/usr/local/bin/agurim
		the agurim binary.
	cgi-bin/
		the cgi directory.
	agurim_home/
		the home direcotry for the web content.
	data_dir/
		the top directory for the datasets.
		the agurim data files are stored under this directory.

		dsname/  # dataset name
		  yyyy.agr # yearly data with 24-hour resolution
		  yyyymm/  # month dir
		    yyyymm.agr # monthly data with 2-hour resolution
		    yyyymmdd/  # day dir
		      yyyymmdd.agr # daily data with 5-min resolution
		      yyyymmdd.HHMMSS.agr # high resolution data

# Install

  0. populate data under 'data_dir'.

  1. install the aguirm binary to '/usr/local/bin/agurim'.

	% cd src;
	% make
	% sudo make install

  2. copy 'agurim/cgi-bin/*' to 'cgi-bin'.
    - edit 'myagurim.cgi'.
      - 'agurimcmd': absolute path to the agurim binary command.
      - 'data_dir': path to the datasets (relative from the cgi-bin page).
      - 'def_dsname': default dataset name.

    if the python path isn't '/usr/local/bin/python', change
    the path in the cgi scripts.

  3. copy `index.html detail.html about.html css/ img/ js/ fonts/`
    to 'agurim_home'.
    - edit 'index.html' and customize 'datasets' if you have multiple datasets.
    - edit 'cgi_path' for 'cgi-bin', in 'js/myagurim.js'.
    - edit 'timeoffset', timezone offset, in 'js/myagurim.js'.

# Usage

	agurim [-dhpP] [other options] [files]
	    other options:
		[-f filter] [-i interval] [-m byte|packet]
		[-n nflows] [-s duration] [-t thresh]
		[-S starttime] [-E endtime]

agurim reads files in the Aguri format, perform re-aggregation, and
print the results to the standard output.  When multiple input files
are specified, the files should be passed in the chronological order.
If no file is specified, agurim reads the data from the standard
input for re-aggregation, but reading from the standard input is not
supported for the plotting mode as the plotting mode needs to read the
data twice.

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


