Enable Phoenix
=================

## 1. Use SQLline to connect secure hbase
```
sqlline.py <zk_quorum>:<zk_port>:<zk_hbase_path>:<principal>:<keytab_file>
// An example:
sqlline.py localhost:2181:/hbase:hbase/localhost@EXAMPLE.COM:/home/hadoop/keytab/hbase.keytab
```

## 2. Configuring phoenix query server

### Update hbase-site.xml
add the following properties:
```
<property>
    <name>phoenix.queryserver.kerberos.principal</name>
    <value>hbase/_HOST@HADOOP.COM</value>
</property>

<property>
    <name>phoenix.queryserver.keytab.file</name>
    <value>/home/hadoop/keytab/hbase.keytab</value>
</property>
```

### Start phoenix query server
```
queryserver.py start
```
