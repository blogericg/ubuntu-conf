#!/bin/bash
# konstruktoid.net

FW_ADMIN="192.168.2.100"
FW_CONF="https://raw.githubusercontent.com/konstruktoid/ubuntu-conf/master/net/firewall.conf"
FW_POLICY="https://raw.githubusercontent.com/konstruktoid/ubuntu-conf/master/net/firewall"
SSH_GRPS="sudo"
VERBOSE="N"
CHANGEME=""		# Add something just to verify that you actually glanced the code

RINPUT=`openssl rand -hex 3`

clear

if [[ $VERBOSE == "Y" ]];
	then
		APTFLAGS="--assume-yes"
	else
		APTFLAGS="-qq --assume-yes"
fi

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

if ! [[ `grep "/tmp" /etc/fstab` ]];
	then
		echo "[X] /tmp settings."
		$SUDO bash -c "echo tmpfs /tmp tmpfs defaults,nosuid,nodev,mode=1777,size=100M 0 0 >> /etc/fstab"
		$SUDO bash -c "echo /tmp /var/tmp tmpfs defaults,nosuid,nodev,bind,mode=1777,size=100M 0 0 >> /etc/fstab"
		$SUDO mount -a
fi

echo "[X] Updating the package index files from their sources."
$SUDO apt-get $APTFLAGS update

echo "[X] Upgrading installed packages."
$SUDO apt-get $APTFLAGS upgrade 

echo "[X] Installing firewall."
$SUDO bash -c "curl -3 -s $FW_CONF > /etc/init/firewall.conf"
$SUDO bash -c "curl -3 -s $FW_POLICY > /etc/init.d/firewall"
$SUDO update-rc.d firewall defaults 2>/dev/null 
$SUDO sed -i "s/ADMIN=\"127.0.0.1\"/ADMIN=\"$FW_ADMIN\"/" /etc/init.d/firewall
$SUDO chmod u+x /etc/init.d/firewall
$SUDO bash -c "/etc/init.d/firewall"

echo "[X] /etc/hosts.*"
$SUDO bash -c "echo sshd : ALL : ALLOW$'\n'ALL: LOCAL, 127.0.0.1 > /etc/hosts.allow"
$SUDO bash -c "echo ALL: PARANOID > /etc/hosts.deny"

echo "[X] /etc/login.defs"
$SUDO sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS\t\tyes/' /etc/login.defs
$SUDO sed -i 's/^UMASK.*/UMASK\t\t077/' /etc/login.defs
$SUDO sed -i 's/^# SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS\t\t10000/' /etc/login.defs

if ! [[ `grep "fs.suid_dumpable = 0" /etc/security/limits.conf` ]];
	then
		echo "[X] /etc/sysctl.conf"
		$SUDO bash -c "echo fs.suid_dumpable = 0 >> /etc/sysctl.conf"
fi

if ! [[ `grep "soft nproc 100" /etc/security/limits.conf` ]];
	then
		echo "[X] /etc/security/limits.conf"
		$SUDO sed -i 's/^# End of file*//' /etc/security/limits.conf
		$SUDO bash -c "echo $'\n'* hard core 0$'\n'* soft nproc 100$'\n'* hard nproc 150$'\n\n'# End of file >> /etc/security/limits.conf"
fi

echo "[X] Installing base packages"
if [[ `$SUDO dmidecode -q --type system | grep -i vmware` ]]; 
	then
		VMTOOLS="open-vm-tools"
fi

$SUDO apt-get $APTFLAGS install libpam-tmpdir libpam-cracklib apparmor-profiles ntp openssh-server $VMTOOLS

if ! [[ `grep "AllowGroups $SSH_GRPS"` ]];
	then
		echo "[X] /etc/ssh/sshd_config"
		$SUDO bash -c "echo $'\n'## Groups allowed to connect$'\n'AllowGroups $SSH_GRPS >> /etc/ssh/sshd_config"
		$SUDO /etc/init.d/ssh restart
fi

echo "[X] Default shell" 
$SUDO sed -i 's/DSHELL=.*/DSHELL=\/bin\/false/' /etc/adduser.conf 
$SUDO sed -i 's/SHELL=.*/SHELL=\/bin\/false/' /etc/default/useradd

echo "[X] Password requirements"
$SUDO sed -i 's/pam_cracklib.so.*/pam_cracklib.so retry=3 minlen=14/' /etc/pam.d/common-password
$SUDO sed -i 's/try_first_pass sha512.*/try_first_pass sha512 remember=5/' /etc/pam.d/common-password

echo "[X] Remove suid bits"
$SUDO chmod -s /bin/fusermount /bin/mount /bin/su /bin/umount /usr/bin/bsd-write /usr/bin/chage /usr/bin/chfn /usr/bin/chsh /usr/bin/mlocate /usr/bin/mtr /usr/bin/newgrp /usr/bin/traceroute6.iputils /usr/bin/wall 

echo "[X] Cleaning."
$SUDO apt-get $APTFLAGS clean
$SUDO apt-get $APTFLAGS autoremove
