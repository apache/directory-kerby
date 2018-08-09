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

MySQL Backend
===============

## Install MySQL

Please refer to [install mysql](https://dev.mysql.com/doc/refman/5.7/en/linux-installation.html).

## Config backend
```
// Url: jdbc url of mysql database; mysqlbackend: name of has mysql backend database; username: mysql user name; password: mysql password
cd kerby-dist/has-dist
sh bin/has-init.sh conf
HasInitTool: config_kdcBackend mysql jdbc:mysql://127.0.0.1:3306/mysqlbackend?createDB=true root passwd
HasInitTool: exit
```

## Config kdc
```
cd kerby-dist/has-dist
sh bin/has-init.sh conf
HasInitTool: config_kdc localhost 88 HADOOP.COM
HasInitTool: exit
```
