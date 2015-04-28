# agurim
agurim: a multi-dimensional flow aggregation tool

This source tree contains the tools to build the agurim web server,
including the source code of the secondary aggregation engine and web
user interface.

The primary aggregation tools for agurim can be found at
https://github.com/necoma/aguri2/


LAYOUT

	/usr/local/bin/agurim
		the agurim binary
	/cgi-bin/
		the cgi directory
	agurim_home
		the home direcotry for the web content
	data_dir/
		the top directory for the datasets

INSTALL

	0. populate data under <data_dir>

	1. install the aguirm binary to /usr/local/bin/agurim

	2. copy agurim/cgi-bin/* to <cgi-bin>

	   edit "myagurim.cgi"
	   	agurimcmd: absolute path to the agurim binary command
		data_dir: path to the datasets (relative from the cgi-bin page)
		def_dsname: # default dataset name

	   if the python path isn't "/usr/local/bin/python", change
	   the path in the cgi scripts.

	3. copy index.html detail.html about.html css/ img/ js/ fonts/ to <agurim_home>

	   edit "index.html" and customize "datasets"

	   edit "cgi_path" for <cgi-bin>, in "js/myagurim.js"
	   edit "timeoffset", timezone offset, in "js/myagurim.js"

