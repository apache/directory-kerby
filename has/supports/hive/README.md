Enable Hive
==============

## Hive on hdfs

### 1. Enabling Kerberos Authentication for HiveServer2
> Update hive-site.xml
```
<property>
  <name>hive.server2.authentication</name>
  <value>KERBEROS</value>
</property>
<property>
  <name>hive.server2.authentication.kerberos.principal</name>
  <value>hive/_HOST@HADOOP.COM</value>
</property>
<property>
  <name>hive.server2.authentication.kerberos.keytab</name>
  <value>/path/to/hive.keytab</value>
</property>
```

### 2. Enable impersonation in HiveServer2
> Update hive-site.xml
```
<property>
  <name>hive.server2.enable.impersonation</name>
  <description>Enable user impersonation for HiveServer2</description>
  <value>true</value>
</property>
```

> Update core-site.xml of hadoop
```
<property>
  <name>hadoop.proxyuser.hive.hosts</name>
  <value>*</value>
</property>
<property>
  <name>hadoop.proxyuser.hive.groups</name>
  <value>*</value>
</property>
```

### 3. Start Hive
> start sevice
```
hive --service metastore &
hive --service hiveserver2 &
```

> start hive shell
```
hive
```
