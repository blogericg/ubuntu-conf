#!/bin/bash
SRC="/etc/apt/sources.list"
SSRC="/etc/apt/security.sources.list"
 
APT="apt-get -q" 
OPT="-o Dir::Etc::SourceList"
 
grep -i security $SRC | grep -v "#" > $SSRC

$APT update
$APT $OPT=$SSRC upgrade

$APT clean
$APT autoclean
$APT autoremove
update-grub 
