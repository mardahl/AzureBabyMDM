#!/bin/bash
FQDN=$1

# From: https://stackoverflow.com/questions/19665863/how-do-i-use-a-self-signed-certificate-for-a-https-node-js-server

# make directories to work from
mkdir -p server/ client/ all/

# Create your very own Root Certificate Authority
openssl genrsa \
  -out all/my-private-root-ca.privkey.pem \
  2048

# Self-sign your Root Certificate Authority
# Since this is private, the details can be as bogus as you like
openssl req \
  -x509 \
  -new \
  -nodes \
  -key all/my-private-root-ca.privkey.pem \
  -days 1024 \
  -out all/my-private-root-ca.cert.pem \
  -subj "/C=US/ST=Washington/L=Sammamish/O=Oofhours Signing Authority Inc/CN=Oofhours.com"

# Create a Device Certificate for each domain,
# such as example.com, *.example.com, awesome.example.com
# NOTE: You MUST match CN to the domain name or ip address you want to use
openssl genrsa \
  -out all/privkey.pem \
  2048

# Create a request from your Device, which your Root CA will sign
openssl req -new \
  -key all/privkey.pem \
  -out all/csr.pem \
  -subj "/C=US/ST=Washington/L=Sammamish/O=Oofhours/CN=${FQDN}"

# Sign the request from Device with your Root CA
openssl x509 \
  -req -in all/csr.pem \
  -CA all/my-private-root-ca.cert.pem \
  -CAkey all/my-private-root-ca.privkey.pem \
  -CAcreateserial \
  -out all/cert.pem \
  -days 500

# Put things in their proper place
rsync -a all/{privkey,cert}.pem server/
cat all/cert.pem > server/fullchain.pem         # we have no intermediates in this case
rsync -a all/my-private-root-ca.cert.pem server/
rsync -a all/my-private-root-ca.cert.pem client/

# create DER format crt for iOS Mobile Safari, etc
openssl x509 -outform der -in all/my-private-root-ca.cert.pem -out client/my-private-root-ca.crt
