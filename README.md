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

	`% cd src; make; sudo make install`

  2. copy 'agurim/cgi-bin/*' to 'cgi-bin'.
    - edit 'myagurim.cgi'.
      - 'agurimcmd': absolute path to the agurim binary command.
      - 'data_dir': path to the datasets (relative from the cgi-bin page).
      - 'def_dsname': default dataset name.

    if the python path isn't '/usr/local/bin/python', change
    the path in the cgi scripts.

    make sure that this cgi-bin directroy is configured properly for
    your web server.  you can try `http://your_server/cgi_path/test.cgi`.

  3. copy `index.html detail.html about.html css/ img/ js/ fonts/`
    to 'agurim_home'.
    - edit 'index.html' and customize 'datasets' if you have multiple datasets.
    - edit 'cgi_path' for 'cgi-bin', in 'js/myagurim.js'.
    - edit 'timeoffset', timezone offset, in 'js/myagurim.js'.



