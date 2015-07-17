#!/bin/bash

java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=n -classpath \
lib/*:. \
-DKERBY_LOGFILE=kdc \
org.apache.kerby.kerberos.kdc.KerbyKdcServer -start $@
