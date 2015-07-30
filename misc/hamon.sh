#!/bin/sh
PROCESS="/usr/sbin/mysqld"
FQDN=$(hostname --fqdn)
RCPT="root"

if [ -z "$(pidof $PROCESS)" ]
  then
  MAIL=$(mktemp)

  {
    echo "$PROCESS not running on $FQDN."
    echo "Initiating Heartbeat Standby and service restart."
    echo
  } >> "$MAIL"

  tail -n5 /var/log/mysql/error.log /var/log/mysql.err /var/log/mysql.log >> "$MAIL"

  /usr/share/heartbeat/hb_standby all >/dev/null 2>&1
  service mysql restart >/dev/null 2>&1

  echo >> "$MAIL"
  tail -n10 /var/log/heartbeat-debug >> "$MAIL"

  mail -s "$PROCESS not running on $FQDN." "$RCPT" < "$MAIL"

  rm "$MAIL"
fi
