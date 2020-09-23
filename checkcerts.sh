#!/bin/bash
# Usage: get validity and hash algo for certificate chain
# Chris Rundle - Sept 2020
# Requires IP:port as Target 

echo
echo "*****************************************************"
echo "*** Certificate Chain Signature Algorithm Checker ***"
echo "*****************************************************"
echo 

if [[ $1 == "" ]]; then
    echo "[!] No target URL provided (e.g. 8.8.8.8 or www.xe.com)";
    exit;
fi

if [[ $1 =~ ":" ]]; then
    echo "[!] Just provide the URL please e.g. google.com";
    exit;
fi

targ1=$1

echo "[?] Which port is the service using? e.g. 443";
read tport
echo

echo && echo "[?] What empty directory should the results be stored in? e.g. CERTS1"
echo "[+] (If it doesn't exist, it will be created.)"
read cdir

if [[ ! -d $cdir ]]; then echo "Creating directory..." && mkdir $cdir; else echo "Using existing directory..."; fi;
sleep .5;

if [ "$(ls -A $cdir)" ]; then
     echo "[!] That directory is not empty - try again.";
     exit;
fi

cd $cdir;

targ2="$targ1:$tport"
echo && echo "[>] Target = $targ2" && echo;

openssl s_client -showcerts -servername $targ1 -verify 5 -connect $targ2 < /dev/null | awk '/BEGIN/,/END/{ if(/BEGIN/){a++}; out="cert"a".crt"; print >out}' && for cert in *.crt; do newname=$(openssl x509 -noout -subject -in $cert | sed -n 's/^.*CN=\(.*\)$/\1/; s/[ ,.*]/_/g; s/__/_/g; s/^_//g;p').pem; mv $cert $newname; echo $cert = $newname; done;
echo "----------------------------------------";
shopt -s nullglob
for p in *.pem
do
# see https://www.openssl.org/docs/man1.0.2/man1/x509.html TEXT OPTIONS section for more info on *certopt* settings.
#openssl x509 -in $p -text -noout -certopt ca_default -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame
openssl x509 -in $p -text -noout -certopt ca_default -certopt no_serial -certopt no_extensions -certopt no_signame
echo "----------------------------------------";
done;

echo "[>] Intermediate .pem files are in the $cdir folder."
echo "[>] Highest cert in the chain is $newname (see above)." && echo

echo "[?] Do you want to view the certificate details for the issuer of that certificate? [YN]";
read gethash;
if [ $gethash == "y" ]; then gethash="Y"; fi;
if [ ! $gethash == "Y" ]; then echo "----------------------------------------" && echo && exit; fi;

echo && echo "Root certificate for $targ2:" && echo "=============================================="
rhash=$(openssl x509 -in $newname -noout -issuer_hash)
echo "Certificate hash = $rhash" && echo
sleep .5 
cat /etc/ssl/certs/$rhash.0 > root.pem
openssl x509 -in root.pem -text -noout -certopt ca_default -certopt no_serial -certopt no_extensions -certopt no_signame
echo "----------------------------------------" && echo;
#
# NOTES:
# ~~~~~~
# If the root cert doesn't download, it's probably already stored on your machine.
# openssl s_client only shows you the certificate chain sent to the client. This chain does not usually include 
# the root certificate itself, which is contained in the local trust store and is not sent by the server.
# Use the "Y" option in the script to get the certificate of the issuer of the highest intermediate certificate.
# To do this manually, find the name of the uppermost cert in the above (intermediate certs) folder, and run
# openssl x509 -in <certname>.pem -noout -issuer_hash
# this will return something like 3513523f (which is the certificate's hash)
# now do cat /etc/ssl/certs/3513523f.0 (you need to append the".0"); copy, paste and save it as root.pem
# now run
# openssl x509 -in root.pem -text -noout -certopt ca_default -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame
# to get the validation you need.


