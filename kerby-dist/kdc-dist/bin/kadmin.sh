#!/bin/bash

DEBUG=
args=
for var in $*; do
  if [ $var == "-D" ]; then
    DEBUG="-Xdebug -Xrunjdwp:transport=dt_socket,address=8001,server=y,suspend=n"
  else
    args="$args $var"
  fi
done

java $DEBUG \
-classpath lib/*:. \
-DKERBY_LOGFILE=kadmin \
org.apache.kerby.kerberos.tool.kadmin.KadminTool $args
