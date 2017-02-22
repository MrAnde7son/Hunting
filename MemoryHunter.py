#!/usr/bin/env python
__author__ = 'Itamar'

### IMPORTS ###
import os
import sys
from subprocess import *
from optparse import OptionParser
import re
import string
import shutil


### GLOBALS ###
powershell_command = ["-exec", "hidden", "frombase64string", "-nopr", "-enc", "iex", "net.webclient"]
powershell_output = ["system.reflection.assemblyname", "token_privilege_enabled", "token_impersonate", "token_duplicate", "token_adjust_privileges", "system.reflection.emit.assemblybuilderaccess", "se_privilege_enabled"]
macro = ["public declare ptrsafe function", ".ShellExecute", "String.FromCharCode", "WScript.Shell"]

def banner():
    # Prints Banner
    print ("""	             __  __                                   _    _             _
		    |  \/  |                                 | |  | |           | |
	            | \  / | ___ _ __ ___   ___  _ __ _   _  | |__| |_   _ _ __ | |_ ___ _ __
        	    | |\/| |/ _ \ '_ ` _ \ / _ \| '__| | | | |  __  | | | | '_ \| __/ _ \ '__|
        	    | |  | |  __/ | | | | | (_) | |  | |_| | | |  | | |_| | | | | ||  __/ |
        	    |_|  |_|\___|_| |_| |_|\___/|_|   \__, | |_|  |_|\__,_|_| |_|\__\___|_|
                                                       __/ |
                                                      |___/                                    """)
    print "\nMemoryHunter - Extracts and scans code from memory.\n\n\n"

def run_volatility_plugin(profile, filename, plugin, outdir,output):
    plugin_result = Popen(['vol.py', '--profile', profile, '-f', filename, plugin, '-D', outdir], stdout=output,stderr=output)
    plugin_result.wait()

def main():
    # READ SYS.ARGV VARIABLES ================================================================
    usage = './memoryHunter.py [VOL_OPTIONS]\nAutomatic volatility plugins runner for Windows 8.1.\n'
    arg_parser = OptionParser(usage=usage)
    arg_parser.add_option("-f", "--filename", dest="filename", help="Specify the memory dump to use", action="store")
    arg_parser.add_option("--profile", dest="profile", help="Specify profile to load.", action="store")
    arg_parser.add_option("-D", "--outdir", dest="outdir", help="Specify directory to write results to.", action="store")
    (options, args) = arg_parser.parse_args(sys.argv)
    if None in vars(options).values():
        print("Not enough arguments supplied. Please use the --help option for help.")
        sys.exit()

    devnull = open(os.devnull, 'w')

    '''# Determines KDBG offset
    print "Determining kdbg offset..."
    kdbg = open('/tmp/kdbg','w')
    kdbgscan = Popen(['vol.py', '--profile', options.profile, '-f', options.filename, 'kdbgscan'], stdout=kdbg,stderr=devnull)
    kdbgscan.wait()
    kdbg.close()
    regex = re.search('KdCopyDataBlock.+(0x\w+)',open('/tmp/kdbg','r').read())
    kdbg_offset = regex.group(1)
    os.remove('/tmp/kdbg')
'''
    # Creates all directories
    dlldir = options.outdir + '/dlldump'
    maldir = options.outdir + '/malfind'
    moddir = options.outdir + '/moddump'

    os.mkdir(options.outdir)
    try:
        os.mkdir(dlldir)
        os.mkdir(maldir)
        os.mkdir(moddir)
        # Report Generation
        result = open(options.outdir + '/report.txt', 'w')
    except:
        print "Error creating directories."
        exit()

    # Extracting code from memory, dlls, potential code injections and kernel modules
    print "Extracting code from memory..."
    run_volatility_plugin(options.profile,options.filename,'dlldump',dlldir+'/',devnull)
    run_volatility_plugin(options.profile,options.filename,'malfind',maldir+'/',devnull)
    run_volatility_plugin(options.profile,options.filename,'moddump',moddir+'/',devnull)

    # Scans extracted code
    print "Scanning results using ClamAV..."
    cmd = Popen(['clamscan', '-r', options.outdir, '-i'], stdout=result,stderr=devnull)
    cmd.wait()

    # Scans for suspicious strings
    print "Seeking suspicious strings..."
    result.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
    result.write("PowerShell Commands Indicators:\n")
    result.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
    for str in powershell_command:
        cmd = Popen(['grep', '-i', str, options.filename], stdout=PIPE, stderr=devnull)
        cmd.wait()
        if cmd.stdout.read() != "":
            result.write("Found " + str + "\n")
    result.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
    result.write("PowerShell Strings Indicators:\n")
    result.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
    for str in powershell_output:
        cmd = Popen(['grep', '-i', str, options.filename], stdout=PIPE, stderr=devnull)
        cmd.wait()
        if cmd.stdout.read() != "":
            result.write("Found " + str + "\n")
    result.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
    result.write("Macro Code Indicators:\n")
    result.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
    for str in macro:
        cmd = Popen(['grep', '-i', str, options.filename], stdout=PIPE, stderr=devnull)
        cmd.wait()
        if cmd.stdout.read() != "":
            result.write("Found " + str + "\n")
    result.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

    # Running yara rules scan
    print "Running yara rules against memory dump..."
    cmd = Popen(['find', './rules/', '-name', '*.yar'], stdout=PIPE, stderr=devnull)
    cmd.wait()
    result.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
    result.write('Yara Rules Hits')
    result.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
    for path in cmd.stdout.read():
        cmd = Popen(['vol.py', '--profile', options.profile, '-f', options.filename, 'yarascan', '--yara-file=', path], stdout=PIPE,stderr=devnull)
        cmd.wait()
        if cmd.stdout.read() != "":
            result.write(cmd.stdout.read())

    devnull.close()
    result.close()
    print "MemoryHunter finished."

if __name__ == '__main__':
    banner()
    main()
    exit()
    #try:
    '''except:
        shutil.rmtree(sys.argv[len(sys.argv)-1])
        print "Unexpected error:", sys.exc_info()[1]
        exit()
'''