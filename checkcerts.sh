#!/bin/bash
# Usage: get validity and hash algo for certificate chain
# Chris Rundle - Sept 2020
# Requires IP:port as Target 

echo
echo "*****************************************************"
echo "*** Certificate Chain Signature Algorithm Checker ***"
echo "*****************************************************"
echo "[>] IP:port as Target" && echo

if [[ $1 == "" ]]; then
    echo "No target provided (e.g. 8.8.8.8:443 or xe.com:443)";
    exit;
fi

if [[ ! $1 =~ ":" ]]; then
    echo "target must include the port, e.g. google:443";
    exit;
fi

echo && echo "What directory should the results be stored in? (e.g. CERTS1)"
read cdir

mkdir $cdir;
sleep 1;

if [ "$(ls -A $cdir)" ]; then
     echo "That directory is not empty - try again.";
     exit;
fi


cd $cdir;

echo && echo "Target = $1" && echo;

openssl s_client -showcerts -verify 5 -connect $1 < /dev/null | awk '/BEGIN/,/END/{ if(/BEGIN/){a++}; out="cert"a".crt"; print >out}' && for cert in *.crt; do newname=$(openssl x509 -noout -subject -in $cert | sed -n 's/^.*CN=\(.*\)$/\1/; s/[ ,.*]/_/g; s/__/_/g; s/^_//g;p').pem; mv $cert $newname; done;

shopt -s nullglob
for p in *.pem
do
openssl x509 -in $p -text -noout -certopt ca_default -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame
echo ----------------------------------------
done;

echo "Files are in the $cdir folder." && echo
