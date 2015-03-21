#!/bin/bash
java -Xdebug -Xrunjdwp:transport=dt_socket,address=1046,server=y,suspend=n \
-cp -cp ../lib/kerb-client-1.0-SNAPSHOT-jar-with-dependencies.jar:../lib/client-tool-1.0-SNAPSHOT.jar \
../lib/server-tool-1.0-SNAPSHOT.jar org.apache.kerby.kerberos.tool.kadmin.Kadmin $@