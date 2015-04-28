#!/usr/local/bin/python
import common
import subprocess
import shlex
import cgi
import json
import ast
import sys

agurimcmd = "/usr/local/bin/agurim"
data_dir = "../"	# path to the datasets (relative from the cgi-bin page)
def_dsname = "dataset"	# default dsname

res = {}

sys.stdout.write("Content-Type: application/json")

sys.stdout.write("\n")
sys.stdout.write("\n")

# parse parameters
fs = cgi.FieldStorage()

duration = int(fs.getfirst('duration', '0'))
end_time = int(fs.getfirst('endTime', '0'))
start_time = int(fs.getfirst('startTime', '0'))
dsname = fs.getfirst('dsname', '')

if dsname:
        datapath = data_dir + dsname
else:
        datapath = data_dir + def_dsname

(files, start_time, end_time) = common.get_fnames(datapath, duration, start_time, end_time)

# generate a command
cmd = agurimcmd + common.generate_cmdargs(fs.getfirst('criteria'), fs.getfirst('interval'), fs.getfirst('threshold'), fs.getfirst('nflows'), duration, start_time, end_time, fs.getfirst('filter'), fs.getfirst('outfmt', 'text'), fs.getfirst('view'), files)

# exec command
#sys.stderr.write('datapath: %s cmd: %s' % (datapath, cmd))        
args = shlex.split(cmd)
try:
        res = subprocess.check_output(args, cwd=datapath, stderr=subprocess.STDOUT)
except subprocess.CalledProcessError as e:
        sys.stderr.write('cmd failed!:' + e.output)

if fs.getfirst('outfmt', 'text') == 'json':
        if isinstance(res, str) and res:
                res = ast.literal_eval(res)
        res['cmd'] = cmd
sys.stdout.write(json.dumps(res, indent=1))

sys.stdout.write("\n")
sys.stdout.close()
