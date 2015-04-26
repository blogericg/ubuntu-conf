#!/bin/bash
facility=(kern user mail daemon auth syslog authpriv)
severity=(emerg alert crit err warn notice info debug)
n=10
host=`hostname -f`

for ((i=1; i<=n; i++))
do
  PRIORITY0="${facility[RANDOM%${#facility[@]}]}" {,}
  PRIORITY1="${severity[RANDOM%${#severity[@]}]}" {,}
  logger -p $PRIORITY0.$PRIORITY1 "$host Syslog Test Message $i/$n"
done
