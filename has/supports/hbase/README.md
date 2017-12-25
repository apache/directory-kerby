Enable HBase
===============

The Hadoop version in HBase should be checked, from 1.0.0 to 1.3.1 the dependency of hadoop version is 2.5.1.

## 1. Apply the patch to hadoop-2.5.1 source code
```
git apply hbase-hadoop-2.5.1.patch
```

## 2. Build
```
mvn clean package -DskipTests
```

## 3. Copy the hadoop-auth jar and hadoop-common jar to hbase lib
```
cp hadoop/hadoop-common-project/hadoop-auth/target/hadoop-auth-2.5.1.jar $HBASE_HOME/lib/
cp hadoop/hadoop-common-project/hadoop-common/target/hadoop-common-2.5.1.jar $HBASE_HOME/lib/
```

## 4. Update hbase security configuration

### Update conf/hbase-site.xml
```
<property>
  <name>hbase.security.authentication</name>
  <value>kerberos</value> 
</property>

<property>
  <name>hbase.rpc.engine</name>
  <value>org.apache.hadoop.hbase.ipc.SecureRpcEngine</value>
</property>

<property> 
  <name>hbase.regionserver.kerberos.principal</name> 
  <value>hbase/_HOST@HADOOP.COM</value> 
</property> 

<property> 
  <name>hbase.regionserver.keytab.file</name> 
  <value>/path/to/hbase.keytab</value> 
</property>

<property> 
  <name>hbase.master.kerberos.principal</name> 
  <value>hbase/_HOST@HADOOP.COM</value> 
</property> 

<property> 
  <name>hbase.master.keytab.file</name> 
  <value>/path/to/hbase.keytab</value> 
</property>
```

### Update /etc/hbase/conf/zk-jaas.conf
```
Client {
      com.sun.security.auth.module.Krb5LoginModule required
      useKeyTab=true
      keyTab="/path/to/hbase.keytab"
      storeKey=true
      useTicketCache=false
      principal="hbase/_HOST@HADOOP.COM";
};
```

> Note "_HOST" should be replaced with the specific hostname.

### Update conf/hbase-env.sh
```
export HBASE_OPTS="$HBASE_OPTS -Djava.security.auth.login.config=/etc/hbase/conf/zk-jaas.conf"
export HBASE_MANAGES_ZK=false
```

### Update conf/hbase-site.xml on each HBase server host
```
<configuration>
  <property>
    <name>hbase.zookeeper.quorum</name>
    <value>$ZK_NODES</value>
  </property>
   
  <property>
    <name>hbase.cluster.distributed</name>
    <value>true</value>
  </property>
</configuration>
```

## 5. Update hadoop configuration to support JSVC instead of SASL

### install jsvc for each host of hadoop cluster
```
sudo apt-get install jsvc
```

> Download commons-daemon-xxx.jar from  http://archive.apache.org/dist/commons/daemon/binaries/

```
export CLASSPATH=$CLASSPATH:/path/to/commons-daemon-xxx.jar
```

### Update hadoop/etc/hadoop/hadoop-env.sh
```
export HADOOP_SECURE_DN_USER=root
export HADOOP_SECURE_DN_PID_DIR=$HADOOP_HOME/$DN_USER/pids
export HADOOP_SECURE_DN_LOG_DIR=$HADOOP_HOME/$DN_USER/logs

export JSVC_HOME=/usr/bin
```

### Disable https in hadoop/etc/hadoop/hdfs-site.xml

***REMOVE*** following configurations
```
<!-- HTTPS config -->
<property>
  <name>dfs.http.policy</name>
  <value>HTTPS_ONLY</value>
</property>
<property>
  <name>dfs.data.transfer.protection</name>
  <value>integrity</value>
</property>
```

### Update hadoop/etc/hadoop/hdfs-site.xml
```
<property>
    <name>dfs.datanode.address</name>
    <value>0.0.0.0:1004</value> 
</property>
<property>
    <name>dfs.datanode.http.address</name>
    <value>0.0.0.0:1006</value>
</property>
```

> The datanode ports range from 0 to 1023.

## 6. Start hbase

### Restart namenode and datanode in jsvc
```
sbin/stop-dfs.sh // stop hdfs first

sbin/hadoop-daemon.sh start nameonode // start namenode
sbin/start-secure-dns.sh // start datanode
```

### Start hbase
```
bin/start-hbase.sh
```
