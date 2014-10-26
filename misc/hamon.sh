#!/bin/bash
PROCESS="/usr/sbin/mysqld"
FQDN=`hostname --fqdn`
RCPT="root"

if [ -z "$(pidof $PROCESS)" ]
	then
	MAIL=`mktemp`

	echo "$PROCESS not running on $FQDN." > $MAIL
	echo "Initiating Heartbeat Standby and service restart." >> $MAIL
	echo >> $MAIL

	tail -n5 /var/log/mysql/error.log /var/log/mysql.err /var/log/mysql.log >> $MAIL
	
	/usr/share/heartbeat/hb_standby all &> /dev/null
	service mysql restart &> /dev/null

	echo >> $MAIL
	tail -n10 /var/log/heartbeat-debug >> $MAIL

	cat $MAIL | mail -s "$PROCESS not running on $FQDN." $RCPT
	
	rm $MAIL
fi
