#!/bin/bash
confdir=/etc/kerby/krb/conf
java -cp ../lib/kerb-client-1.0-SNAPSHOT-jar-with-dependencies.jar:../lib/kinit-1.0-SNAPSHOT.jar org.apache.kerby.kerberos.tool.kinit.Kinit ${confdir} $@