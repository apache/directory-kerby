#!/bin/bash

java -Xdebug -Xrunjdwp:transport=dt_socket,address=8004,server=y,suspend=n \
-classpath lib/*:. \
org.apache.kerby.kerberos.tool.klist.KlistTool $@
