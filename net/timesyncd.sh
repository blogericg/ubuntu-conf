function timesyncd {
  echo "Configuring systemd-timesyncd"

  SERVERPOOL="0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org pool.ntp.org"
  LATENCY="50"
  SERVERS="4"
  APPLY="NO"
  CONF="/etc/systemd/timesyncd.conf"
  
  SERVERARRAY=()
  FALLBACKARRAY=()
  TMPCONF=`mktemp --tmpdir ntpconf.XXXXX`

  echo "[Time]" > $TMPCONF

  if ! [[ `find /bin/ping -perm -4000` ]];
    then
      PONG="$SUDO ping -c2"
    else
      PONG="ping -c2"
  fi

  for s in `dig +noall +answer +nocomments $SERVERPOOL | awk '{print $5}'`;
    do
      if [[  $NUMSERV -ge $SERVERS ]];
        then
          break
      fi
      PINGSERV=`$PONG $s | grep 'rtt min/avg/max/mdev' |awk -F "/" '{printf "%.0f\n",$6}'`
      if [[ $PINGSERV -gt "1" && $PINGSERV -lt "$LATENCY" ]];
        then
          OKSERV=`nslookup $s|grep "name = "|awk '{print $4}'|sed 's/.$//'`
            if [[ $OKSERV && $NUMSERV -lt $SERVERS && ! (( $(grep "$OKSERV" $TMPCONF) )) ]];
              then
                echo "$OKSERV has latency < $LATENCY"
                SERVERARRAY+=("$OKSERV")
                ((NUMSERV++))
            fi
      fi
  done

  for l in $SERVERPOOL;
    do
      if [[ $FALLBACKSERV -lt "2" ]];
        then
          FALLBACKARRAY+=("$l")
          ((FALLBACKSERV++))
        else
          break
      fi
    done

  echo "NTP=${SERVERARRAY[@]}" >> $TMPCONF
  echo "FallbackNTP=${FALLBACKARRAY[@]}" >> $TMPCONF

  if [[ $APPLY = "YES" ]];
    then
      $SUDO bash -c "cat $TMPCONF > $CONF"
      $SUDO systemctl restart systemd-timesyncd
      rm $TMPCONF
    else
      echo "Configuration saved to $TMPCONF."
  fi
  ((i++))
}

timesyncd
