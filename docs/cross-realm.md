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

cross-realm
============

### Synchronize time of realms
The time of realms should be synchronized.

### Add the same special principals in realms
```
cd kerby-dist/kdc-dist
sh bin/kadmin.sh [server-conf-dir] -k [keytab]
// A.EXAMPLE.COM realm to access a service in the B.EXAMPLE.COM realm
KadminTool.local: addprinc -pw [same-password] krbtgt/B.EXAMPLE.COM@A.EXAMPLE.COM
// Make sure that both principals have matching key version numbers and encryption types
KadminTool.local: getprinc krbtgt/B.EXAMPLE.COM@A.EXAMPLE.COM
```

### Configure krb5.conf of realms

* config realms and domain_realms sections, make sure the realms are contained.

* config capaths section, which contains the realm chain.

An example of krb5.conf:
```
[realms]
  A.EXAMPLE.COM = {
    kdc = A.EXAMPLE.COM
  }
  B.EXAMPLE.COM = {
    kdc = B.EXAMPLE.COM
  }

[domain_realm]
  .A.EXAMPLE.COM = a.example.com
  A.EXAMPLE.COM = a.example.com
  .B.EXAMPLE.COM = b.example.com
  B.EXAMPLE.COM = b.example.com

[capaths]
  A.EXAMPLE.COM = {
    B.EXAMPLE.COM = .
  }
  B.EXAMPLE.COM = {
    A.EXAMPLE.COM = .
  }
```

### Validate
```
cd kerby-dist/tool-dist
sh bin/kinit.sh -conf [client-conf-dir] -c [credential-cache-of-local-realm] -S [principal-name-of-remote-realm]
```
