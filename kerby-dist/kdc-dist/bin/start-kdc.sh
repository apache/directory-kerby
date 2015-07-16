#!/bin/bash

java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=n -classpath \
lib/*:. \
org.apache.kerby.kerberos.kdc.KerbyKdcServer -start $@
