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

Kerby-dist
============

The distribution of Kerby.

### 1. To run with a standalone kdc server, kdcinit, kadmin, kinit and klist

* 1. Generate libraries for distribution:
```
mvn package -Pdist
```

* 2. Run kdcinit:
```
cd kerby-dist/kdc-dist
sh bin/kdcinit.sh [server-conf-dir] [keytab]
```
The admin principal will be exported into [keytab], it will be used by kadmin tool for the authentication. 

* 3. Start kerby-kdc-server:
```
cd kerby-dist/kdc-dist
sh bin/start-kdc.sh [server-conf-dir] [work-dir]
```

* 4. Run kadmin to add or delete principals:
```
cd kerby-dist/kdc-dist
sh bin/kadmin.sh [server-conf-dir] -k [keytab]
```
  The keytab file is created by the kdcinit.
  In kadmin, you can type "?" for help.

* 5. Run kinit:
```
cd kerby-dist/tool-dist
sh bin/kinit.sh -conf [client-conf-dir] [principal-name]
```

* 6. Run klist:
```
cd kerby-dist/tool-dist
sh bin/klist.sh -c [credentials-cache]
```

  If you don't specify [server-conf-dir] in step 2, 3 or 4, it will be set as /etc/kerby. In [server-conf-dir], there should be kdc.conf, backend.conf. 
  And if you don't specify [client-conf-dir] in step 5, it will be set as /etc/, there should be krb5.conf.

An example of kdc.conf:
```
[kdcdefaults]
    kdc_host = localhost
    kdc_tcp_port = 8015
    kdc_realm = TEST.COM
```
An example of json backend backend.conf:
```
kdc_identity_backend = org.apache.kerby.kerberos.kdc.identitybackend.JsonIdentityBackend
backend.json.dir = /tmp/kerby/jsonbackend
```
An example of zookeeper backend backend.conf:
```
kdc_identity_backend = org.apache.kerby.kerberos.kdc.identitybackend.ZookeeperIdentityBackend
data_dir = /tmp/kerby/zookeeper/data
data_log_dir = /tmp/kerby/zookeeper/datalog
```
An example of krb5.conf:
```
[libdefaults]
    kdc_realm=TEST.COM
    kdc_tcp_port = 8015
```

### 2. Anonymous PKINIT configuration
generate a private key:
```
openssl genrsa -out cakey.pem 2048
```

generate the CA certificate:
```
openssl req -key cakey.pem -new -x509 -out cacert.pem -days 3650
```

generate the KDC key:
```
openssl genrsa -out kdckey.pem 2048
```

generate a certificate request:
```
openssl req -new -out kdc.req -key kdckey.pem
```

generate the certificate:
```
openssl x509 -req -in kdc.req -CAkey cakey.pem -CA cacert.pem -out kdc.pem -extfile pkinit_extensions -extensions kdc_cert -CAcreateserial
```

On the KDC, you must set the pkinit_identity variable to provide the KDC certificate.
Configure the following relation in the[kdcdefaults] section of the KDC’s kdc.conf file
```
pkinit_identity = FILE:/var/lib/krb5kdc/kdc.pem,/var/lib/krb5kdc/kdckey.pem
```

On client hosts, you must set the pkinit_anchors variable in order to trust the issuing authority for the KDC certificate. Configure the following relation in krb5.conf file.
```
pkinit_anchors = FILE:/etc/krb5/cacert.pem
```

create the principalWELLKNOWN/ANONYMOUS using the command:
```
sh bin/kadmin.sh [server-conf-dir] -k [keytab]
addprinc -randkey WELLKNOWN/ANONYMOUS
```

To obtain anonymous credentials on a client, run:
```
sh bin/kinit.sh -conf [client-conf-dir] -n
```
The resulting tickets will have the client name WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS.


