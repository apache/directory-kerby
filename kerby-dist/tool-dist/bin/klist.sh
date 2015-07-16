#!/bin/bash

java -Xdebug -Xrunjdwp:transport=dt_socket,address=8004,server=n,suspend=n \
-classpath lib/*:. \
 org.apache.kerby.kerberos.tool.klist.KlistTool $@
