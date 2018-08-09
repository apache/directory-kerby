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
