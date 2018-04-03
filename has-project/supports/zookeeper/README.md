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
