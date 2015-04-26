#!/bin/bash
DRIFTFILE=`grep driftfile /etc/ntp.conf |awk '{print $2}'`
PPM='0.0864'

if test -r $DRIFTFILE; then
    DRIFT=`cat $DRIFTFILE`
  else
    echo "$DRIFTFILE is not available."
    exit
fi

S=`echo "$PPM $DRIFT" | awk '{s=$1*$2; {print s}}'`
PEER=`ntpq -n -c lpeers | grep "*" |awk '{print $1}' | tr -d "*"`
NPEER=`nslookup $PEER | grep "name = " | awk '{print $4}'`

echo "`hostname -f` is off by about $S seconds per day relative to sys.peer $PEER ($NPEER)"
