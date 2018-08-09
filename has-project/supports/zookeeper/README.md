<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

Enable ZooKeeper
===================

## 1. Create the dependency jars
```
cd directroy-kerby/has-project/supports/zookeeper
mvn clean package
```

## 2. Copy the jars to ZooKeeper lib directory
```
cp directroy-kerby/has-project/supports/zookeeper/lib/* $ZOOKEEPER_HOME/lib/
```

## 3. Copy the conf file to ZooKeeper conf directory
```
cp directroy-kerby/has-project/supports/zookeeper/conf/* $ZOOKEEPER_HOME/conf/
```

## 4. Update Zookeeper security configuration files
> Update $ZOO_CONF_DIR/jaas.conf
> Replace "_HOST" with the specific hostname for each host
```
Server {
  com.sun.security.auth.module.Krb5LoginModule required
  useKeyTab=true
  keyTab="/path/to/zookeeper.keytab"
  storeKey=true
  useTicketCache=true
  principal="zookeeper/_HOST@HADOOP.COM";
};

Client {
  com.sun.security.auth.module.Krb5LoginModule required
  useKeyTab=true
  keyTab="/home/hdfs/keytab/hbase.keytab"
  storeKey=true
  useTicketCache=false
  principal="zookeeper/_HOST@HADOOP.COM";
};
```

> Update conf/zoo.cfg
```
authProvider.1=org.apache.zookeeper.server.auth.SASLAuthenticationProvider
jaasLoginRenew=3600000
kerberos.removeHostFromPrincipal=true
kerberos.removeRealmFromPrincipal=true
```

## 5. Verifying the configuration
```
zkCli.sh -server hostname:port
create /znode1 data sasl:zookeeper:cdwra
getAcl /znode1
```

> The results from getAcl should show that the proper scheme and permissions were applied to the znode.    
> like: 'sasl,'zookeeper
