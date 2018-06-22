Enable Presto
================

## 1. Hive Security Configuration
Update catalog/hive.properties, Add the following properties:
```
<!-- Config to connect Kerberized hive metastore -->
hive.metastore.authentication.type=KERBEROS
hive.metastore.service.principal=hbase/_HOST@HADOOP.COM
hive.metastore.client.principal=hbase/_HOST@HADOOP.COM
hive.metastore.client.keytab=/path/to/hbase.keytab

<!-- Config to connect kerberized hdfs -->
hive.hdfs.authentication.type=KERBEROS
hive.hdfs.presto.principal=hbase/_HOST@HADOOP.COM
hive.hdfs.presto.keytab=/path/to/hbase.keytab
```

> Note "_HOST" should be replaced with the specific hostname.

## 2. Restart presto server
```
/bin/launcher restart
```
