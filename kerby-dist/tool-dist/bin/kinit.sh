#!/bin/bash

DEBUG=
args=
for var in $*; do
  if [ $var == "-D" ]; then
    DEBUG="-Xdebug -Xrunjdwp:transport=dt_socket,address=8002,server=y,suspend=n"
  else
    args="$args $var"
  fi
done

java $DEBUG \
-classpath lib/*:. \
-DKERBY_LOGFILE=kinit \
org.apache.kerby.kerberos.tool.kinit.KinitTool $args
