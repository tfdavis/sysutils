#!/usr/bin/python
#-------------------------------------------------------------------------------
# SCRIPT:       hostsdenyupdater.py
# DESCRIPTION:  Script which will scan auth.log and detect failed login attempts.
#               If we detect that a particular IP address has numerous failed
#               login attempts, then assume the worst and add the IP address to 
#               the /etc/hosts.deny file.
#
# VERSION:      $Id$
# 
# TODO - add option for multi-day limits.  (Currently only supports a limit of 
#             x knocks in 1 day.  Should support x knocks across y days).
#
#
#
#
#-------------------------------------------------------------------------------
import re
import string
import operator
from ConfigReader import ConfigReader
from optparse import OptionParser
import os.path
import sys
import socket

#-------------------------------------------------------------------------------
# Parse command line arguments

parser = OptionParser()

parser.add_option("-a", "--authlog",  action="store", type="string", dest="authlogfile",
                   help="Specify the location of your auth.log file")

parser.add_option("-f", "--hostsfile",  action="store", type="string", dest="hostsdenyfile",
                   help="Specify the location of your /etc/hosts.deny file")

parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False,
                   help="Print some extra info to STDOUT.")

parser.add_option("-l", "--limit", type="int", action="store", dest="limit", default=20,
                   help="Specify the number of SSH failures which triggers banning the IP")

parser.add_option("-n", "--noupdate", action="store_true", dest="noupdate", default=False,
                   help="Run the script and print debug info without updating hosts.deny file.")

parser.add_option("-e", "--email", action="store", dest="email", type="string",
                   help="Specify an email address to notify when new IPs are blocked.")

(options, args) = parser.parse_args()

authlogfile   = options.authlogfile
hostsdenyfile = options.hostsdenyfile
verbose       = options.verbose
knock_limit   = options.limit
noupdate      = options.noupdate
email_addr    = options.email

#-------------------------------------------------------------------------------
# Check command line arguments

if not isinstance(options.authlogfile, str) or len(authlogfile) == 0:
	parser.error("Must specify location of auth.log file")
	sys.exit(1)

if not isinstance(options.hostsdenyfile, str) or len(hostsdenyfile) == 0:
	parser.error("Must specify location of hosts.deny file")
	sys.exit(1)

if not os.path.exists(authlogfile):
	print "FATAL ERROR: " + authlogfile + " does not exist"
	sys.exit(1)

if not os.path.exists(hostsdenyfile):
	print "FATAL ERROR: " + hostsdenyfile + " does not exist"
	sys.exit(1)

if noupdate:
	verbose = True

#-------------------------------------------------------------------------------
# Scan the auth log file to detect failed login attempts

dates        = {}
#usernames    = {}
ip_addresses = {}
email_msg    = ""

f = open(authlogfile, 'r')
for line in f:
	# sample line:
	# Dec 17 01:22:51 fra sshd[13845]: Failed password for invalid user root from 12.23.34.45 port 45807 ssh2
	if re.search("Failed password for invalid user", line):
		prog = re.compile(r"^(?P<month>[A-Z]+) +(?P<mday>\d+) \d+:\d+:\d+ [a-z0-9]+ sshd\[\d+\]: Failed password for invalid user (?P<username>.*?) from (?P<ip_addr>\d+\.\d+\.\d+\.\d+) port", re.IGNORECASE)
		m = prog.match(line)
		if m:
			thisDate = m.group('month')  + " " +  m.group('mday')
			thisUsername = m.group('username')
			thisIPAddr   = m.group('ip_addr')
			
			if not thisDate in dates:
				dates[thisDate] = {}

			if thisIPAddr in dates[thisDate]:
				dates[thisDate][thisIPAddr] += 1
			else:
				dates[thisDate][thisIPAddr] = 1
			
			#if thisUsername in usernames:
			#	usernames[thisUsername] += 1
			#else:
			#	usernames[thisUsername] = 1
				
			#if thisIPAddr in ip_addresses:
			#	ip_addresses[thisIPAddr] += 1
			#else:
			#	ip_addresses[thisIPAddr] = 1
		else:
			print "PARSE ERROR on line: " +  line

#-------------------------------------------------------------------------------
# Get the current list of denied IP addreses.  We'll use that to ensure we don't
# add duplicates

denied_ips   = []

cr = ConfigReader(hostsdenyfile)
cr.read()
config = cr.get_config()
for line in config:
	parts = line.split(":")
	denied_ips.append(parts[1].strip())

status_update = "DEBUG: hosts.deny file currently has " + str(len(denied_ips)) + " denied IP addresses."

email_msg += status_update + "\n"
if verbose:
	print status_update

#-------------------------------------------------------------------------------
# Determine if there are any new IP addresses that we should ban.

new_banned_ips = []
for date in dates.iterkeys():
	#print "DATE: " + date
	#print dates[date]
	#print " "
	for ip_addr in dates[date].iterkeys():
		if dates[date][ip_addr] > knock_limit:
			if not ip_addr in denied_ips:
				new_banned_ips.append(ip_addr)
				status_update = "DEBUG: Will add " + ip_addr + " for " + date + " because it has " + str(dates[date][ip_addr]) + " entries."
				email_msg += status_update + "\n"
				if verbose:
					print status_update

status_update = "DEBUG: Adding " + str(len(new_banned_ips)) + " new IP addresses to hosts.deny file."
email_msg += status_update + "\n"
if verbose:
	print status_update

#-------------------------------------------------------------------------------
# If there are new IP addresses to ban, then update the hosts.deny file.

if len(new_banned_ips) > 0 and not noupdate:
	f = open(hostsdenyfile, 'a')
	for ip in new_banned_ips:
		f.write("ALL: "+ ip + "\n")
	f.close
	email_msg += "\nUpdated " + hostsdenyfile + " with these changes.\n"
else:
	email_msg += "\nNo changes to " + hostsdenyfile + " due to noupdate flag\n"

#-------------------------------------------------------------------------------
# All done, just send the email if necessary

if len(new_banned_ips) > 0 and isinstance(email_addr, str):
	SUBJECT = "Modifications to hosts.deny on " + socket.gethostname()
	sendmail_location = "/usr/sbin/sendmail"
	p = os.popen("%s -t" % sendmail_location, "w")
	p.write("From: %s\n" % "root@localhost")
	p.write("To: %s\n" % email_addr)
	p.write("Subject: " + SUBJECT + "\n")
	p.write("\n") 
	p.write(email_msg)
	p.close()
