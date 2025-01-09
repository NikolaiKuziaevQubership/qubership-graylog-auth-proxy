#!/bin/bash
echo "Enter bind password for LDAP user: "
stty -echo
read passwd
stty echo
echo $passwd | base64 > $1
