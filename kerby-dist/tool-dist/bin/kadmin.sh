#!/bin/bash
java -Xdebug -Xrunjdwp:transport=dt_socket,address=1045,server=y,suspend=n -cp ../lib/kadmin-1.0-SNAPSHOT-jar-with-dependencies.jar org.apache.kerby.kerberos.tool.kadmin.Kadmin $@