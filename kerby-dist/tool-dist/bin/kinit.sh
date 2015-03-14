#!/bin/bash
confdir=/etc/kerby/krb/conf
java -jar ../kinit/kinit-1.0-SNAPSHOT-jar-with-dependencies.jar ${confdir} $@
