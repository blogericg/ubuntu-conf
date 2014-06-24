#!/bin/bash
# konstruktoid.net

SERVERPOOL="0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org pool.ntp.org"
PEERS=""
LATENCY="50"
SERVERS="4"
APPLY="no"
CONF="/etc/ntp.conf"
TMPCONF=`mktemp --tmpdir ntpconf.XXXXX`

if ! [[ `id | grep sudo` || `id -u` = '0' ]];
        then
                echo "Not root and not in the sudo group. Exiting."
                echo
                exit
fi

if [[ `id -u` = '0' ]];
        then
                SUDO=''
        else
                SUDO='sudo'
fi
 
echo "
driftfile /var/lib/ntp/ntp.drift
 
statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
filegen clockstats file clockstats type day enable

restrict -4 default kod notrap nomodify nopeer noquery
restrict -6 default kod notrap nomodify nopeer noquery

restrict 127.0.0.1
restrict ::1
" > $TMPCONF

if ! [[ $PEERS = "" ]];
	then
		for p in $PEERS;
        		do
        		echo "restrict $p" >> $TMPCONF
		done

echo >> $TMPCONF
 
		for p in $PEERS;
        		do
        		echo "peer $p" >> $TMPCONF
		done

echo >> $TMPCONF
fi

NUMSERV="0"

if ! [[ `find /bin/ping -perm -4000` ]];
	then
		PONG="$SUDO ping -c2"
	else
		PONG="ping -c2"
fi

for s in `dig +noall +answer +nocomments $SERVERPOOL | awk '{print $5}'`;
        do
                PINGSERV=`$PONG $s | grep 'rtt min/avg/max/mdev' |awk -F "/" '{printf "%.0f\n",$6}'`
		if [[ $PINGSERV -gt "1" && $PINGSERV -lt "$LATENCY" ]];
                	then
                                OKSERV=`nslookup $s|grep "name = "|awk '{print $4}'|sed 's/.$//'`
                                if [[ $OKSERV && $NUMSERV -lt $SERVERS && ! (( $(grep "$OKSERV" $TMPCONF) )) ]];
                			then
                                               	echo "server $OKSERV" >> $TMPCONF
						((NUMSERV++))
                                        fi
		fi
done

if [[ $NUMSERV == "0" ]];
	then 
	for l in $SERVERPOOL;
		do
		echo "server $l" >> $TMPCONF
	done
fi

if [[ $APPLY = "YES" ]];
	then
	$SUDO bash -c "cat $TMPCONF > $CONF"
	$SUDO service ntp restart
	rm $TMPCONF
	else
	echo "Configuration saved to $TMPCONF."
fi
exit
