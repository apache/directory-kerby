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
