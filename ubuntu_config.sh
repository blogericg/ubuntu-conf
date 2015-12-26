#!/bin/bash
#
# Documentation: 
# Red Hat 6 STIG - Version 1 Release 4
# Guide to the Secure Configuration of Red Hat Enterprise Linux 5
# CIS Ubuntu 12.04 LTS Server Benchmark v1.0.0
# https://wiki.ubuntu.com/Security/Features
# https://help.ubuntu.com/community/StricterDefaults
#

FW_ADMIN="192.168.2.100"
SSH_GRPS="sudo"
FW_CONF="https://raw.githubusercontent.com/konstruktoid/ubuntu-conf/master/net/firewall.conf"
FW_POLICY="https://raw.githubusercontent.com/konstruktoid/ubuntu-conf/master/net/firewall"
SYSCTL_CONF="https://raw.githubusercontent.com/konstruktoid/ubuntu-conf/master/misc/sysctl.conf"
AUDITD_RULES="https://raw.githubusercontent.com/konstruktoid/ubuntu-conf/master/misc/audit.rules"
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

i="0"

echo "[$i] Installing firewall."
$SUDO bash -c "curl -s $FW_CONF > /etc/init/firewall.conf"
$SUDO bash -c "curl -s $FW_POLICY > /etc/init.d/firewall"
$SUDO update-rc.d firewall defaults 2>/dev/null 
$SUDO sed -i "s/ADMIN=\"127.0.0.1\"/ADMIN=\"$FW_ADMIN\"/" /etc/init.d/firewall
$SUDO chmod u+x /etc/init.d/firewall
$SUDO bash -c "/etc/init.d/firewall"
((i++))

echo "[$i] /etc/fstab"
$SUDO bash -c "echo tmpfs /tmp tmpfs defaults,nosuid,nodev,mode=1777,size=100M 0 0 >> /etc/fstab"
$SUDO bash -c "echo /tmp /var/tmp tmpfs defaults,nosuid,nodev,bind,mode=1777,size=100M 0 0 >> /etc/fstab"
$SUDO sed -i '/floppy/d' /etc/fstab
$SUDO mount -a
((i++))

echo "[$i] Updating the package index files from their sources."
$SUDO $APT update
((i++))

echo "[$i] Upgrading installed packages."
$SUDO $APT upgrade 
((i++))

echo "[$i] /etc/hosts.*"
$SUDO bash -c "echo sshd : ALL : ALLOW$'\n'ALL: LOCAL, 127.0.0.1 > /etc/hosts.allow"
$SUDO bash -c "echo ALL: PARANOID > /etc/hosts.deny"
((i++))

echo "[$i] /etc/login.defs"
$SUDO sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS\t\tyes/' /etc/login.defs
$SUDO sed -i 's/^UMASK.*/UMASK\t\t077/' /etc/login.defs
$SUDO sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t\t1/' /etc/login.defs
$SUDO sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t\t30/' /etc/login.defs
$SUDO sed -i 's/DEFAULT_HOME.*/DEFAULT_HOME no/' /etc/login.defs
$SUDO sed -i 's/USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' /etc/login.defs
$SUDO sed -i 's/^# SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS\t\t10000/' /etc/login.defs
((i++))

echo "[$i] /etc/sysctl.conf"
$SUDO bash -c "curl -s $SYSCTL_CONF > /etc/sysctl.conf"
$SUDO service procps start
((i++))

echo "[$i] /etc/security/limits.conf"
$SUDO sed -i 's/^# End of file*//' /etc/security/limits.conf
$SUDO bash -c "echo * hard maxlogins 10 >> /etc/security/limits.conf"
$SUDO bash -c "echo * hard core 0$'\n'* soft nproc 100$'\n'* hard nproc 150$'\n\n'# End of file >> /etc/security/limits.conf"
((i++))

echo "[$i] Adduser / Useradd" 
$SUDO sed -i 's/DSHELL=.*/DSHELL=\/bin\/false/' /etc/adduser.conf 
$SUDO sed -i 's/SHELL=.*/SHELL=\/bin\/false/' /etc/default/useradd
$SUDO sed -i 's/^# INACTIVE=.*/INACTIVE=35/' /etc/default/useradd
((i++))

echo "[$i] Root access"
$SUDO sed -i 's/^#+ : root : 127.0.0.1/+ : root : 127.0.0.1/' /etc/security/access.conf
$SUDO bash -c "echo console > /etc/securetty"
((i++))

echo "[$i] Installing base packages."
if [[ `$SUDO dmidecode -q --type system | grep -i vmware` ]]; 
	then
		VM="open-vm-tools"
fi

$SUDO bash -c "echo postfix postfix/main_mailer_type select Internet Site | debconf-set-selections"
$SUDO bash -c "echo postfix postfix/mailname string `hostname -f` | debconf-set-selections"

$SUDO $APT install aide-common apparmor-profiles auditd haveged libpam-cracklib libpam-tmpdir ntp openssh-server postfix $VM

echo "[$i] /etc/ssh/sshd_config"
$SUDO bash -c "echo $'\n'## Groups allowed to connect$'\n'AllowGroups $SSH_GRPS >> /etc/ssh/sshd_config"
$SUDO sed -i 's/^LoginGraceTime 120/LoginGraceTime 20/' /etc/ssh/sshd_config
$SUDO sed -i 's/^PermitRootLogin without-password/PermitRootLogin no/' /etc/ssh/sshd_config
$SUDO bash -c "echo ClientAliveInterval 900 >> /etc/ssh/sshd_config"
$SUDO bash -c "echo ClientAliveCountMax 0 >> /etc/ssh/sshd_config"
$SUDO bash -c "echo PermitUserEnvironment no >> /etc/ssh/sshd_config"
$SUDO bash -c "echo Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc >> /etc/ssh/sshd_config"
$SUDO /etc/init.d/ssh restart
((i++))

echo "[$i] Passwords and authentication"
$SUDO sed -i 's/^password[\t].*.pam_cracklib.*/password\trequired\t\t\tpam_cracklib.so retry=3 maxrepeat=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=4/' /etc/pam.d/common-password
$SUDO sed -i 's/try_first_pass sha512.*/try_first_pass sha512 remember=24/' /etc/pam.d/common-password
$SUDO sed -i 's/nullok_secure//' /etc/pam.d/common-auth
((i++))

echo "[$i] Cron and at"
$SUDO bash -c "echo root > /etc/cron.allow"
$SUDO bash -c "echo root > /etc/at.allow"
((i++))

echo "[$i] Ctrl-alt-delete"
$SUDO sed -i 's/^exec.*/exec \/usr\/bin\/logger -p security.info \"Ctrl-Alt-Delete pressed\"/' /etc/init/control-alt-delete.conf
((i++))

echo "[$i] Blacklisting kernel modules"
$SUDO bash -c "echo >> /etc/modprobe.d/blacklist.conf"
for mod in dccp sctp rds tipc net-pf-31 bluetooth usb-storage;
do 
	$SUDO bash -c "echo install $mod /bin/false >> /etc/modprobe.d/blacklist.conf"
done
((i++))

echo "[$i] Auditd"
$SUDO sed -i 's/^space_left_action =.*/space_left_action = email/' /etc/audit/auditd.conf
$SUDO bash -c "curl -s $AUDITD_RULES > /etc/audit/audit.rules"
$SUDO sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="audit=1"/' /etc/default/grub
$SUDO bash -c "curl -s $AUDITD_RULES > /etc/audit/audit.rules"
$SUDO update-grub 2> /dev/null
((i++))

echo "[$i] Aide"
$SUDO sed -i 's/^Checksums =.*/Checksums = sha512/' /etc/aide/aide.conf
((i++))

echo "[$i] .rhosts"
for dir in `cat /etc/passwd | awk -F ":" '{print $6}'`;
do
        find $dir -name "hosts.equiv" -o -name ".rhosts" -exec rm -f {} \; 2> /dev/null
        if [[ -f /etc/hosts.equiv ]];
                then
                rm /etc/hosts.equiv
        fi
done
((i++))

echo "[$i] Remove users"
for users in games gnats irc news uucp; 
do 
	sudo userdel -r $users 2> /dev/null
done

echo "[$i] Remove suid bits"
for p in /bin/fusermount /bin/mount /bin/ping /bin/ping6 /bin/su /bin/umount /usr/bin/bsd-write /usr/bin/chage /usr/bin/chfn /usr/bin/chsh /usr/bin/mlocate /usr/bin/mtr /usr/bin/newgrp /usr/bin/pkexec /usr/bin/traceroute6.iputils /usr/bin/wall /usr/sbin/pppd;
do 
	oct=`stat -c "%a" $p |sed 's/^4/0/'`
	ug=`stat -c "%U %G" $p`
	$SUDO dpkg-statoverride --remove $p 2> /dev/null
	$SUDO dpkg-statoverride --add $ug $oct $p 2> /dev/null
	$SUDO chmod -s $p
done

for SHELL in `cat /etc/shells`; do
	if [ -x $SHELL ]; then
		$SUDO chmod -s $SHELL
	fi
done

((i++))

echo "[$i] Cleaning."
$SUDO $APT clean
$SUDO $APT autoclean
$SUDO apt-get -qq autoremove
((i++))

echo
echo "[$i] Running Aide, this will take a while"
$SUDO aideinit --yes
$SUDO cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
((i++))

echo

if [ -f /var/run/reboot-required ]; then
        cat /var/run/reboot-required
fi

echo
