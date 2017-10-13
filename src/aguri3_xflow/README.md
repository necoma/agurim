# aguri3_xflow

The flow parser tool for aguri3

aguri3_xflow is the flow parser tool for aguri3, to read sFlow or
NetFlow records.
aguri3_xflow reads sFlow or NetFlow from a UDP socket, translate the
input records to the aguri_flow_records, and write them to the
standard output.
sFlow (version 4 and 5) and NetFlow (version 5 and 9) are supported.

## Install

	% make
	% sudo make install

## Usage

	aguri3_xflow

  + `-4`:  
    Use only IPv4.  By default, both IPv4 and IPv6 sockets are used.

  + `-6`:  
    Use only IPv6.  By default, both IPv4 and IPv6 sockets are used.

  + `-a agent`:  
    Receive only from the specified agent.  By default, it receives
    from any agent.

  + `-d`:  
    Enable debug, and print human readable outputs instead of binary
    aguri_flow_records.
  
  + `-p port`:  
    Listen on the specified port.  By default, port 6343 is used for
    sFlow and port 2055 is used for NetFlow.

  + `-s sampling rate`:  
    Use the specified sampling rate when the sampling rate is not
    available in the flow export.

  + `-t sflow|netflow`:  
    Specify the flow record type.  Currently, 'sflow' and 'netflow'
    are supported.  Default is 'sflow'.

  + `-v`: Enable the verbose mode.

## Examples

To read netflow data from port 2055, and produce aggregated flow
records every 60 seconds:

	aguri3_xflow -t netflow -p 2055 | aguri3 -i 60

Similary, to read sflow data from port 6343, and produce aggregated
flow records every 60 seconds: 

	aguri3_xflow -t sflow -p 6343 | aguri3 -i 60

To set the sampling rate to 2014 for netflow:

	aguri3_xflow -t netflow -s 1024

To see human readable outputs:

	aguri3_xflow -d -t netflow


