#!/bin/bash

java -Xdebug -Xrunjdwp:transport=dt_socket,address=8004,server=y,suspend=n \
-classpath lib/*:. \
-DKERBY_LOGFILE=klist \
org.apache.kerby.kerberos.tool.klist.KlistTool $@
