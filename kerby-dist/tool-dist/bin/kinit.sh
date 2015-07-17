#!/bin/bash

java -Xdebug -Xrunjdwp:transport=dt_socket,address=8002,server=y,suspend=n \
-classpath lib/*:. \
-DKERBY_LOGFILE=kinit \
org.apache.kerby.kerberos.tool.kinit.KinitTool $@
