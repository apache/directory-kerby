#!/bin/bash

find -iname \*.pem  -exec rm {} \;
find -iname \*.txt\*  -exec rm {} \;
find -iname \*serial\*  -exec rm {} \;
rm -f root.cnf rsa-intermediate.cnf dsa-intermediate.cnf dsa-intermediate/dsa.params
