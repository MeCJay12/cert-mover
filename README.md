# cert-mover
Collection of scripts for moving and transforming SSL certificates for different systems and platforms

## certUpdateLnx.sh

Used to move LetsEncrypt format certificates on the local machine to a remote SSH/Rsync machine and reboot remote web server.

## certUpdatePan.py

Used to upload a certificate from local disk to a Palo Alto device API. Includes tool for generating API key.

## npm2.py
### Incomplete

Used for downloading a certificate from one Nginx Proxy Manager API and uploading it to another. Pending [bug](https://github.com/NginxProxyManager/nginx-proxy-manager/issues/4245) fix in NPM. 
