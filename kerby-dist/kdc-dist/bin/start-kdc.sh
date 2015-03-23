#!/bin/bash
java -Xdebug -Xrunjdwp:transport=dt_socket,address=1044,server=y,suspend=n \
-cp ../lib/json-backend-1.0-SNAPSHOT-jar-with-dependencies.jar:\
../lib/ldap-backend-1.0-SNAPSHOT-jar-with-dependencies.jar:\
../lib/zookeeper-backend-1.0-SNAPSHOT-jar-with-dependencies.jar:\
../lib/kerb-server-1.0-SNAPSHOT-jar-with-dependencies.jar:\
../lib/kerby-kdc-1.0-SNAPSHOT.jar org.apache.kerby.kerberos.kdc.KerbyKdcServer $@
