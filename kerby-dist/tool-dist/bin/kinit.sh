#!/bin/bash
java -Xdebug -Xrunjdwp:transport=dt_socket,address=1045,server=y,suspend=n \
-cp ../lib/kerb-client-1.0-SNAPSHOT-jar-with-dependencies.jar:\
../lib/client-tool-1.0-SNAPSHOT.jar org.apache.kerby.kerberos.tool.kinit.Kinit $@
