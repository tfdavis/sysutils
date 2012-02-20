#!/bin/sh 
#-------------------------------------------------------------------------------
# SCRIPT:        firewall.sh
# DESCRIPTION:   A basic iptables shell script
# VERSION:       $Id$
#
#-------------------------------------------------------------------------------

set -e 
iptables="/sbin/iptables" 
#modprobe="/sbin/modprobe" 

load () { 
	#echo "Loading kernel modules..." 
	#$modprobe ip_tables 
	#$modprobe ip_conntrack 
	#$modprobe iptable_filter 
	#$modprobe ipt_state 
	#echo "Kernel modules loaded." 

	echo "Loading rules..." 
	$iptables -P FORWARD DROP 
	$iptables -P INPUT DROP 

	#--------------------------------------------------------------------------
	# Specific ports and rules.

	#--------------------------------------------------------------------------
	# FTP 
	#$iptables -A INPUT -p tcp -m tcp --destination-port 21 -j ACCEPT     # ftp

	#--------------------------------------------------------------------------
	# SSH: ssh rules with some brute force attack protection
	$iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH -j ACCEPT

	$iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 6 --rttl \
	 --name SSH -j LOG --log-prefix "SSH_brute_force "
	$iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 \
	 --hitcount 6 --rttl --name SSH -j DROP

	#--------------------------------------------------------------------------
	# Allow mail traffic (sendmail or postfix)
	# currently only have outbout allowed.
	$iptables -A OUTPUT -o eth0 -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT

	#--------------------------------------------------------------------------
	# Web Traffic

	$iptables -A INPUT -p tcp -m tcp --destination-port 80 -j ACCEPT 
	$iptables -A INPUT -p tcp -m tcp --destination-port 443 -j ACCEPT 

	# Web DOS protection:
	$iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

	#--------------------------------------------------------------------------
	# allow established traffic
	$iptables -A INPUT -p ALL -m state --state ESTABLISHED,RELATED -j ACCEPT 

	#--------------------------------------------------------------------------
	# allow all from loopback
	$iptables -A INPUT -s 127.0.0.1 -j ACCEPT 

	#--------------------------------------------------------------------------
	# allow outbound DNS queries and the replies, too.
	$iptables -A OUTPUT -p udp -o eth0 --dport 53 --sport 1024:65535 -j ACCEPT
	$iptables -A INPUT -p udp -i eth0 --sport 53 --dport 1024:65535 -j ACCEPT


	#--------------------------------------------------------------------------
	# Allow incoming and outgoing pings
	$iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
	$iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

	$iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
	$iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

	echo "Rules loaded." 
} 

flush () { 
	echo "Flushing rules..." 
	$iptables -P FORWARD ACCEPT 
	$iptables -F INPUT 
	$iptables -P INPUT ACCEPT 
	echo "Rules flushed." 
} 

case "$1" in 
	start|restart) 
		flush 
		load  
		;; 
	stop) 
		flush  
		;; 
	*) 
		echo "usage: start|stop|restart."  
		;; 
esac 

exit 0

