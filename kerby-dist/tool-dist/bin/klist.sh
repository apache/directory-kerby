#!/bin/bash
java -Xdebug -Xrunjdwp:transport=dt_socket,address=1045,server=y,suspend=n \
-cp ../lib/kerb-client-api-all-1.0-SNAPSHOT.jar:\
../lib/kerby-asn1-1.0-SNAPSHOT.jar:\
../lib/client-tool-1.0-SNAPSHOT.jar org.apache.kerby.kerberos.tool.klist.KlistTool $@
