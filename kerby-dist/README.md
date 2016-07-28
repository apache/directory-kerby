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

## 1. How to play with kerby kdc server

#### 1. Generate libraries for distribution:
```
mvn package -Pdist
```

#### 2. Run kdcinit:
```
cd kerby-dist/kdc-dist
sh bin/kdcinit.sh [server-conf-dir] [keytab]
```
The admin principal will be exported into [keytab], it will be used by kadmin tool for the authentication. 

#### 3. Start kerby-kdc-server:
```
cd kerby-dist/kdc-dist
sh bin/start-kdc.sh [server-conf-dir] [work-dir]
```

#### 4. Run kadmin to add or delete principals:
```
cd kerby-dist/kdc-dist
sh bin/kadmin.sh [server-conf-dir] -k [keytab]
```
  The keytab file is created by the kdcinit.
  In kadmin, you can type "?" for help.

#### 5. Run kinit:
```
cd kerby-dist/tool-dist
sh bin/kinit.sh -conf [client-conf-dir] [principal-name]
```

#### 6. Run klist:
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
    kdc_udp_port = 8015
    kdc_realm = EXAMPLE.COM
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
    kdc_realm=EXAMPLE.COM
    kdc_tcp_port = 8015
    kdc_udp_port = 8015
```

## 2. Anonymous PKINIT configuration
#### 1. Generate a client private key:
```
openssl genrsa -out cakey.pem 2048
```

#### 2. Generate the CA certificate:
```
openssl req -key cakey.pem -new -x509 -out cacert.pem -days 3650
```

#### 3. Generate the KDC key:
```
openssl genrsa -out kdckey.pem 2048
```

#### 4. Generate a certificate request:
```
openssl req -new -out kdc.req -key kdckey.pem
```

#### 5. Generate the kdc certificate:
First, you will need a file named pkinit_extensions containing the following:
```
[kdc_cert]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
issuerAltName=issuer:copy
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name

[kdc_princ_name]
realm=EXP:0,GeneralString:${ENV::REALM}
principal_name=EXP:1,SEQUENCE:kdc_principal_seq

[kdc_principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:kdc_principals

[kdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:${ENV::REALM}
```
Then:
```
openssl x509 -req -in kdc.req -CAkey cakey.pem -CA cacert.pem -out kdc.pem -extfile pkinit_extensions -extensions kdc_cert -CAcreateserial
```

#### 6 . On the KDC, you must set the pkinit_identity variable to provide the KDC certificate.
Configure the following relation in the[kdcdefaults] section of the KDC’s kdc.conf file
```
pkinit_identity = FILE:/var/lib/krb5kdc/kdc.pem,/var/lib/krb5kdc/kdckey.pem
```

#### 7. On client hosts, you must set the pkinit_anchors variable in order to trust the issuing authority for the KDC certificate. Configure the following relation in krb5.conf file.
```
pkinit_anchors = FILE:/etc/krb5/cacert.pem
```

#### 8. Create the principalWELLKNOWN/ANONYMOUS using the command:
```
sh bin/kadmin.sh [server-conf-dir] -k [keytab]
addprinc -randkey WELLKNOWN/ANONYMOUS
```

#### 9. To obtain anonymous credentials on a client, run:
```
sh bin/kinit.sh -conf [client-conf-dir] -n
```
The resulting tickets will have the client name WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS.

#### References: 
[1]http://web.mit.edu/Kerberos/krb5-1.12/doc/admin/pkinit.html#creating-certificates
[2]http://k5wiki.kerberos.org/wiki/Pkinit_configuration


## 3. Run remote kadmin steps
#### 1. Generate libraries for distribution:
```
mvn package -Pdist
```

#### 2. Run kdcinit:
```
cd kerby-dist/kdc-dist
sh bin/kdcinit.sh [kdc-server-conf-dir] [keytab]
```
The admin principal will be exported into [keytab], it will be used by kadmin tool for the authentication. 

#### 3. Start kerby-kdc-server:
```
cd kerby-dist/kdc-dist
sh bin/start-kdc.sh [kdc-server-conf-dir] [work-dir]
```

#### 4. Run kadmin server
```
cd kerby-dist/kdc-dist
sh bin/admin-server.sh [admin-server-conf-dir]
```
An example of adminClient.conf:
```
[libdefaults]
    default_realm = EXAMPLE.COM
    admin_port = 65417
    keytab_file = admin.keytab
    protocol = adminprotocol
    server_name = localhost
```
The keytab_file is the keytab file path created by the kdcinit.

#### 5. Run remote kadmin client to add or delete principals:
```
cd kerby-dist/kdc-dist
sh bin/remote-admin-client.sh [admin-client-conf-dir]
```
An example of adminServer.conf:
```
[libdefaults]
    default_realm = EXAMPLE.COM
    admin_realm = EXAMPLE.COM
    admin_port = 65417
    keytab_file = protocol.keytab
    protocol = adminprotocol
    server_name = localhost
```
The keytab_file is the keytab file path created by the kdcinit.
The kdc-server-conf-dir, admin-client-conf-dir, admin-server-conf-dir are the same dir.
