#!/bin/bash

if [[ ! -f privkey.pem ]]; then
    openssl genrsa -out privkey.pem 4096
    openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095
fi
