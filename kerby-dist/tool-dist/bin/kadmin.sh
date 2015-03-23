#!/bin/bash
java -Xdebug -Xrunjdwp:transport=dt_socket,address=1046,server=y,suspend=n \
-cp ../lib/json-backend-1.0-SNAPSHOT-jar-with-dependencies.jar:\
../lib/ldap-backend-1.0-SNAPSHOT-jar-with-dependencies.jar:\
../lib/zookeeper-backend-1.0-SNAPSHOT-jar-with-dependencies.jar:\
../lib/server-tool-1.0-SNAPSHOT-jar-with-dependencies.jar org.apache.kerby.kerberos.tool.kadmin.Kadmin $@