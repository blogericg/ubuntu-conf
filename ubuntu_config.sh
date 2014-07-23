#!/bin/bash
# konstruktoid.net

FW_ADMIN="192.168.2.100"
SSH_GRPS="sudo"
FW_CONF="https://raw.githubusercontent.com/konstruktoid/ubuntu-conf/master/net/firewall.conf"
FW_POLICY="https://raw.githubusercontent.com/konstruktoid/ubuntu-conf/master/net/firewall"
SYSCTL_CONF="https://raw.githubusercontent.com/konstruktoid/ubuntu-conf/master/misc/sysctl.conf"
VERBOSE="N"
CHANGEME=""		# Add something just to verify that you actually glanced the code

clear

RINPUT=`openssl rand -hex 3`

if [[ $VERBOSE == "Y" ]];
	then
		APTFLAGS="--assume-yes"
	else
		APTFLAGS="--quiet=2 --assume-yes"
fi

APT="aptitude $APTFLAGS"

if [[ $CHANGEME == "" ]];
	then
		echo "Please read the code".
		echo
		exit
fi

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

if ! [[ `lsb_release -i |grep 'Ubuntu'` ]];
	then
		echo "Ubuntu only. Exiting."
		echo
		exit
fi

echo -n "If you understand what this script will do, please write $RINPUT here: "
read INPUT

if ! [[ "$INPUT" == "$RINPUT" ]];
	then
		echo "Turing test failed. Exiting."
		echo
		exit
	else
		echo "Let it begin."
fi

echo "[X] Installing firewall."
$SUDO bash -c "curl -3 -s $FW_CONF > /etc/init/firewall.conf"
$SUDO bash -c "curl -3 -s $FW_POLICY > /etc/init.d/firewall"
$SUDO update-rc.d firewall defaults 2>/dev/null 
$SUDO sed -i "s/ADMIN=\"127.0.0.1\"/ADMIN=\"$FW_ADMIN\"/" /etc/init.d/firewall
$SUDO chmod u+x /etc/init.d/firewall
$SUDO bash -c "/etc/init.d/firewall"

if ! [[ `grep "/tmp" /etc/fstab` ]];
	then
		echo "[X] /tmp settings."
		$SUDO bash -c "echo tmpfs /tmp tmpfs defaults,nosuid,nodev,mode=1777,size=100M 0 0 >> /etc/fstab"
		$SUDO bash -c "echo /tmp /var/tmp tmpfs defaults,nosuid,nodev,bind,mode=1777,size=100M 0 0 >> /etc/fstab"
		$SUDO mount -a
fi

echo "[X] Updating the package index files from their sources."
$SUDO $APT update

echo "[X] Upgrading installed packages."
$SUDO $APT upgrade 

echo "[X] /etc/hosts.*"
$SUDO bash -c "echo sshd : ALL : ALLOW$'\n'ALL: LOCAL, 127.0.0.1 > /etc/hosts.allow"
$SUDO bash -c "echo ALL: PARANOID > /etc/hosts.deny"

echo "[X] /etc/login.defs"
$SUDO sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS\t\tyes/' /etc/login.defs
$SUDO sed -i 's/^UMASK.*/UMASK\t\t077/' /etc/login.defs
$SUDO sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t\t1/' /etc/login.defs
$SUDO sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t\t30/' /etc/login.defs
$SUDO sed -i 's/DEFAULT_HOME.*/DEFAULT_HOME no/' /etc/login.defs
$SUDO sed -i 's/USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' /etc/login.defs
$SUDO sed -i 's/^# SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS\t\t10000/' /etc/login.defs

echo "[X] /etc/sysctl.conf"
$SUDO bash -c "curl -3 -s $SYSCTL_CONF > /etc/sysctl.conf"
$SUDO service procps start

if ! [[ `grep "soft nproc 100" /etc/security/limits.conf` ]];
	then
		echo "[X] /etc/security/limits.conf"
		$SUDO sed -i 's/^# End of file*//' /etc/security/limits.conf
		$SUDO bash -c "echo $'\n'* hard core 0$'\n'* soft nproc 100$'\n'* hard nproc 150$'\n\n'# End of file >> /etc/security/limits.conf"
fi

echo "[X] Default shell" 
$SUDO sed -i 's/DSHELL=.*/DSHELL=\/bin\/false/' /etc/adduser.conf 
$SUDO sed -i 's/SHELL=.*/SHELL=\/bin\/false/' /etc/default/useradd

echo "[X] Root access"
$SUDO sed -i 's/^#+ : root : 127.0.0.1/+ : root : 127.0.0.1/' /etc/security/access.conf
$SUDO bash -c "echo console > /etc/securetty"

echo "[X] Installing base packages."
if [[ `$SUDO dmidecode -q --type system | grep -i vmware` ]]; 
	then
		VM="open-vm-tools"
fi

$SUDO $APT install aide libpam-tmpdir libpam-cracklib apparmor-profiles ntp openssh-server haveged $VM

echo "[X] /etc/ssh/sshd_config"
if ! [[ `$SUDO grep "AllowGroups" /etc/ssh/sshd_config` ]];
	then
		$SUDO bash -c "echo $'\n'## Groups allowed to connect$'\n'AllowGroups $SSH_GRPS >> /etc/ssh/sshd_config"
fi

$SUDO sed -i 's/^LoginGraceTime 120/LoginGraceTime 20/' /etc/ssh/sshd_config
$SUDO /etc/init.d/ssh restart

echo "[X] Passwords and authentication"
$SUDO sed -i 's/^password[\t].*.pam_cracklib.*/password\trequired\t\t\tpam_cracklib.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=4/' /etc/pam.d/common-password
$SUDO sed -i 's/try_first_pass sha512.*/try_first_pass sha512 remember=5/' /etc/pam.d/common-password
$SUDO sed -i 's/nullok_secure//' /etc/pam.d/common-auth

echo "[X] Cron and at"
$SUDO bash -c "echo root > /etc/cron.allow"
$SUDO bash -c "echo root > /etc/at.allow"

echo "[X] Blacklisting kernel modules"
$SUDO bash -c "echo blacklist dccp >> /etc/modprobe.d/blacklist.conf"
$SUDO bash -c "echo blacklist sctp >> /etc/modprobe.d/blacklist.conf"
$SUDO bash -c "echo blacklist rds >> /etc/modprobe.d/blacklist.conf"
$SUDO bash -c "echo blacklist tipc >> /etc/modprobe.d/blacklist.conf"

echo "[X] Remove suid bits"
for p in /bin/fusermount /bin/mount /bin/ping /bin/ping6 /bin/su /bin/umount /usr/bin/bsd-write /usr/bin/chage /usr/bin/chfn /usr/bin/chsh /usr/bin/mlocate /usr/bin/mtr /usr/bin/newgrp /usr/bin/pkexec /usr/bin/traceroute6.iputils /usr/bin/wall /usr/sbin/pppd;
do 
        oct=`stat -c "%a" $p |sed 's/^4/0/'`
        ug=`stat -c "%U %G" $p`
        $SUDO dpkg-statoverride --remove $p
        $SUDO dpkg-statoverride --add $ug $oct $p
        $SUDO chmod -s $p
done

echo "[X] Cleaning."
$SUDO $APT clean
$SUDO $APT autoclean
$SUDO apt-get -qq autoremove

echo

if [ -f /var/run/reboot-required ]; then
        cat /var/run/reboot-required
fi

echo
