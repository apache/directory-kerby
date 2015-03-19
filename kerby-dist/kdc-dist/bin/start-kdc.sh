#!/bin/bash
java -Xdebug -Xrunjdwp:transport=dt_socket,address=1044,server=y,suspend=n -cp ../lib/kerb-server-1.0-SNAPSHOT-jar-with-dependencies.jar:../lib/Json-identity-backend-1.0-SNAPSHOT.jar:../lib/ldap-identity-backend-1.0-SNAPSHOT.jar:../lib/zookeeper-backend-1.0-SNAPSHOT.jar:../lib/kerby-kdc-1.0-SNAPSHOT.jar org.apache.kerby.kerberos.kdc.server.KerbyKdcServer $@
