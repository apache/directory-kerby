#!/bin/bash

java -Xdebug -Xrunjdwp:transport=dt_socket,address=8005,server=y,suspend=n -classpath \
lib/*:. \
-DKERBY_LOGFILE=kdcinit \
org.apache.kerby.kerberos.tool.kdcinit.KdcInitTool $@
