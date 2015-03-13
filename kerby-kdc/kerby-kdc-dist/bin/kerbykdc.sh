#!/bin/bash
confdir=/etc/kerby/kdc.conf
workingdir=/usr/kerby/kdc/
java -jar ../kerby-kdc/kerby-kdc-1.0-SNAPSHOT-jar-with-dependencies.jar -start ${confdir} ${workingdir}