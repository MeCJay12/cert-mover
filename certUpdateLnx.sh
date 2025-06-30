#!/bin/bash

# Directory where cert directories are created; Usually /etc/letsencrypt/live/
SRC="/path/to/certs/"
# Directory on destination server where cert directories should go
DST="/path/where/certs/go/"
# Space seperated list of hostnames or IPs to copy certs to
Servers=("HostnameA" "IPB")
# Space seperated list of names of cert directories
Certs=("CertA" "CertB")
# Username to log into servers with. Permissions for dst directory and reload command and SSH key auth should be setup seperately.
SSH_User="username"
# Rsync options. Recommended to leave alone.
Options="-avuiL"
# If files are updated, the commend to restart the remote web server service.
Reload_Command="docker restart Nginx" # "service Nginx restart"
Reload=false

for Server in "${Servers[@]}" ; do
	for i in "${!Certs[@]}" ; do
		Cert="${Certs[i]}"

		echo "$Server : $Cert"
		Rsync=$(rsync $Options $SRC/$Cert $SRC/../options-ssl-nginx.conf $SRC/../ssl-dhparams.pem $SSH_User@$Server:$DST --out-format='Changed File: %i %n%L')
		echo "$Rsync"

		if [[ ! -z $(echo "$Rsync" | grep "Changed File") ]] ; then
			Reload=true
		fi
	done

	if [[ "$Reload" == "true" ]] ; then
		ssh $SSH_User@$Server $Reload_Command
    echo "Reloading $Server!"
		Reload=false
	fi
done
