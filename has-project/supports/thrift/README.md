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

Enable Thrift
================

## 1. Enable HBase thrift2 server

### Update hbase-site.xml
add the following properties:
```
<property>
  <name>hbase.thrift.keytab.file</name>
  <value>/etc/hbase/conf/hbase.keytab</value>
</property>
<property>
  <name>hbase.thrift.kerberos.principal</name>
  <value>hbase/_HOST@HADOOP.COM</value>
</property>
```

### Restart HBase

### Start thrift server
```
hbase thrift2 start
```

## 2. Write thrift client application
Use keytab file to connect thrift server.
An example of thrift client:
```Java
package com.example.thrifttest;

import org.apache.hadoop.hbase.thrift.generated.Hbase;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;
import java.io.IOException;

public class Thrifttest {
    static { 
        final String principal = "hbase/hostname@HADOOP.COM";
        final String keyTab = "/etc/hbase/conf/hbase.keytab";
        try {
            UserGroupInformation.loginUserFromKeytab(user, keyPath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void start()  {
        try {  
            TTransport socket = new TSocket("192.168.x.xxx", 9090);
            TProtocol protocol = new TBinaryProtocol(socket, true, true);
            Hbase.Client client = new Hbase.Client(protocol);
        } catch (TTransportException e) {  
            e.printStackTrace();  
        } catch (TException e) {  
            e.printStackTrace();  
        }
    }

    public static void main(String[] args) {
        Thrifttest c = new Thrifttest();
        c.start();
    }
}
```
