#!/bin/bash
#-------------------------------------------------------------------------------
# quick and dirty way to monitor if apache is running.  If it's not send an 
# alert and restart the process.
#-------------------------------------------------------------------------------

EMAIL=''
SERVICE='apache2'
HOST=`hostname`
TMPFILE='/tmp/'`basename $0`"-$$.data"
ERRORLOG='/var/log/apache2/error.log'

#-------------------------------------------------------------------------------

ps -ef | grep -v grep | grep -q $SERVICE
RC=$?

if [ ! $RC -eq 0 ]; then
	echo "$SERVICE is not running on $HOST.  Attempting Restart" > $TMPFILE
	echo >> $TMPFILE

	if [ ! -z $ERRORLOG ]; then
		echo "Last 5 error.log entries:" >> $TMPFILE
		echo >> $TMPFILE
		tail -5 $ERRORLOG  >> $TMPFILE
		echo >> $TMPFILE
	fi

	/etc/init.d/apache2 start
	RC2=$?

	if [ $RC2 -eq 0 ]; then
		echo "Restart Successful" >> $TMPFILE
	else
		echo "Restart Failed" >> $TMPFILE
	fi

	mail -s "WARNING: $SERVICE is not running on $HOST" $EMAIL < $TMPFILE
	
	rm $TMPFILE
fi
