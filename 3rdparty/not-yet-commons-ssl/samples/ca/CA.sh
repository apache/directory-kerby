#!/bin/bash

echo
echo "WARNING:  This script creates fake test SSL certificates that expire after 2038."
echo "          Because of date/time issues on 32 bit unix with dates after 2038, this"
echo "          script can only be run on 64 bit unix machines."
echo

export DAYS=14610 # 40 years
export ROOT_SUBJ="/1.2.840.113549.1.9.1=juliusdavies@gmail.com/CN=root/OU=not-yet-commons-ssl/O=juliusdavies.ca/L=Victoria/ST=BC/C=CA";
export  RSA_SUBJ="/1.2.840.113549.1.9.1=juliusdavies@gmail.com/CN=rsa-intermediate/OU=not-yet-commons-ssl/O=juliusdavies.ca/L=Victoria/ST=BC/C=CA";
export  DSA_SUBJ="/1.2.840.113549.1.9.1=juliusdavies@gmail.com/CN=dsa-intermediate/OU=not-yet-commons-ssl/O=juliusdavies.ca/L=Victoria/ST=BC/C=CA";
export TEST_SUBJ="/1.2.840.113549.1.9.1=juliusdavies@gmail.com/CN=test/OU=not-yet-commons-ssl/O=juliusdavies.ca/L=Victoria/ST=BC/C=CA";

export CA=root
sed s/demoCA/$CA/ openssl.cnf > $CA.cnf
export PRIV=$CA/private
export ROOT_PRIV=$PRIV
mkdir -p       $PRIV
mkdir -p       $CA/newcerts
touch          $CA/index.txt
if [ ! -f "$CA/serial" ]; then
  date +%Y%m%d > $CA/serial
fi
echo
echo "Attempting to make $CA/cacert.pem"
openssl req -newkey rsa:2048 -days $DAYS -nodes -subj $ROOT_SUBJ -keyout $PRIV/cakey.pem -out $CA/careq.pem
openssl ca -config $CA.cnf -create_serial -out $CA/cacert.pem -days $DAYS -batch -keyfile $PRIV/cakey.pem -selfsign -extensions v3_ca -infiles $CA/careq.pem


export CA=rsa-intermediate
sed s/demoCA/$CA/ openssl.cnf > $CA.cnf
export PRIV=$CA/private
mkdir -p       $PRIV
mkdir -p       $CA/newcerts
touch          $CA/index.txt
if [ ! -f "$CA/serial" ]; then
  date +%Y%m%d > $CA/serial
fi
echo
echo "Attempting to make $CA/cacert.pem"
openssl req -newkey rsa:2048 -days $DAYS -nodes -subj $RSA_SUBJ -keyout $PRIV/cakey.pem -out $CA/careq.pem
openssl ca -config root.cnf -create_serial -out $CA/cacert.pem -days $DAYS -batch -keyfile $ROOT_PRIV/cakey.pem -extensions v3_ca -infiles $CA/careq.pem


export CA=dsa-intermediate
sed s/demoCA/$CA/ openssl.cnf > $CA.cnf
export PRIV=$CA/private
mkdir -p       $PRIV
mkdir -p       $CA/newcerts
touch          $CA/index.txt
if [ ! -f "$CA/serial" ]; then
  date +%Y%m%d > $CA/serial
fi
echo
echo "Attempting to make $CA/cacert.pem"
openssl dsaparam -genkey 2048 -out $CA/dsa.params
openssl req -newkey dsa:$CA/dsa.params -days $DAYS -nodes -subj $DSA_SUBJ -keyout $PRIV/cakey.pem -out $CA/careq.pem
openssl ca -config root.cnf -create_serial -out $CA/cacert.pem -days $DAYS -batch -keyfile $ROOT_PRIV/cakey.pem -extensions v3_ca -infiles $CA/careq.pem


export CA=dsa-intermediate
export PRIV=$CA/private
echo
echo "Attempting to make test-dsa-cert.pem"
openssl req -new -key rsa.key -days $DAYS -subj $TEST_SUBJ -out testreq.pem
openssl ca -config dsa-intermediate.cnf -create_serial -out test-dsa-cert.pem -days $DAYS -batch -keyfile $PRIV/cakey.pem -infiles testreq.pem

export CA=rsa-intermediate
export PRIV=$CA/private
echo
echo "Attempting to make test-rsa-cert.pem"
openssl ca -config rsa-intermediate.cnf -create_serial -out test-rsa-cert.pem -days $DAYS -batch -keyfile $PRIV/cakey.pem -infiles testreq.pem

cat test-rsa-cert.pem rsa-intermediate/cacert.pem root/cacert.pem > test-rsa-chain.pem
cat test-dsa-cert.pem dsa-intermediate/cacert.pem root/cacert.pem > test-dsa-chain.pem
