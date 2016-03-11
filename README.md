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

Apache Kerby
============

Apache Kerby, as an [Apache Directory](http://directory.staging.apache.org/) sub project, is a Java Kerberos binding. It provides a rich, intuitive and interoperable implementation, library, KDC and various facilities that integrates PKI, OTP and token (OAuth2) as desired in modern environments such as cloud, Hadoop and mobile.

![](https://github.com/apache/directory-kerby/blob/trunk/docs/logo.png)

### The Initiatives/Goals 
- Aims as a Java Kerberos binding, with rich and integrated facilities that integrate Kerberos, PKI and token (OAuth2) for both client and server sides.
- Provides client APIs at the Kerberos protocol level to interact with a KDC server through AS and TGS exchanges.
- Provides a standalone KDC server that supports various identity backends including memory based, Json file based, LDAP based and even Zookeeper based.
- Provides an embedded KDC server that applications can easily integrate into products, unit tests or integration tests.
- Supports FAST/Preauthentication framework to allow popular and useful authentication mechanisms.
- Supports PKINIT mechanism to allow clients to request tickets using x509 certificate credentials.
- Supports Token Preauth mechanism to allow clients to request tickets using JWT tokens.
- Supports OTP mechanism to allow clients to request tickets using One Time Password.
- Provides support for JAAS, GSSAPI and SASL frameworks that applications can leverage.
- Minimal dependencies, the core part is ensured to depend only on JRE and SLF4J, for easy use and maintenance.

### KrbClient APIs
A Krb client API for applications to interact with KDC.  
Please look at [kerb-client](docs/1.0.0-rc2/krbclient.md) for details.

### Kadmin
Server side admin facilities.  
Please look at [kerb-admin](docs/1.0.0-rc2/kadmin.md) for details.

### KdcServer
Kerberos Server API.  
Please look at [kerb-server](docs/1.0.0-rc2/kdcserver.md) for details.

### SimpleKdcServer
A simplified Kdc server. It can be imported by other project to work as a kdc server.  
Please look at [kerb-simplekdc](docs/1.0.0-rc2/simplekdc.md) for details.

### ASN-1 support
A model driven ASN-1 encoding and decoding framework implemented with Java.  
Please look at [kerby-asn1](docs/1.0.0-rc2/kerby-asn1.md) for details.

### How to play with the standalone KDC
Please look at [Kerby KDC](kerby-dist/README.md) for details.

### Kerberos Crypto and Encryption Types
- Implementing des, des3, rc4, aes, camellia encryption and corresponding checksum types
- Interoperates with MIT Kerberos and Microsoft AD
- Independent of Kerberos code in JRE, but relies on JCE

Similar to [MIT krb5 encryption types](http://web.mit.edu/kerberos/krb5-1.14/doc/admin/conf_files/kdc_conf.html#encryption-types):

| Encryption Type | Description |
| --------------- | ----------- |
| des-cbc-crc | DES cbc mode with CRC-32 (weak) |
| des-cbc-md4 | DES cbc mode with RSA-MD4 (weak) |
| des-cbc-md5 | DES cbc mode with RSA-MD5 (weak) |
| des3-cbc-sha1 des3-hmac-sha1 des3-cbc-sha1-kd | Triple DES cbc mode with HMAC/sha1 |
| des-hmac-sha1 | DES with HMAC/sha1 (weak) |
| aes256-cts-hmac-sha1-96 aes256-cts AES-256 | CTS mode with 96-bit SHA-1 HMAC |
| aes128-cts-hmac-sha1-96 aes128-cts AES-128 | CTS mode with 96-bit SHA-1 HMAC |
| arcfour-hmac rc4-hmac arcfour-hmac-md5 | RC4 with HMAC/MD5 |
| arcfour-hmac-exp rc4-hmac-exp arcfour-hmac-md5-exp | Exportable RC4 with HMAC/MD5 (weak) |
| camellia256-cts-cmac camellia256-cts | Camellia-256 CTS mode with CMAC |
| camellia128-cts-cmac camellia128-cts | Camellia-128 CTS mode with CMAC |
| des | The DES family: des-cbc-crc, des-cbc-md5, and des-cbc-md4 (weak) |
| des3 | The triple DES family: des3-cbc-sha1 |
| aes | The AES family: aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96 |
| rc4 | The RC4 family: arcfour-hmac |
| camellia | The Camellia family: camellia256-cts-cmac and camellia128-cts-cmac |

### Identity Backend
A standalone KDC server that can integrate various identity backends including:
- MemoryIdentityBackend.
  - It is default Identity Backend, and no cofiguration is needed. This backend is for no permanent storage requirements.
- JsonIdentityBackend.
  - It implemented by Gson which is used to convert Java Objects into their JSON representation and convert a JSON string to an equivalent Java object. A json file will be created in "backend.json.dir". This backend is for small, easy, development and test environment.
- ZookeeperIdentityBackend.
  - Currently it uses an embedded Zookeeper. In follow up it will be enhanced to support standalone Zookeeper cluster for
  replication and reliability. Zookeeper backend would be a good choice for high reliability, high performance and high scalability requirement and scenarios. 
- LdapIdentityBackend.
  - The Ldap server can be standalone or embedded using ApacheDS server as the backend. It is used when there is exist ldap server.
- MavibotBackend.
  - A backend based on Apache Mavibot(an MVCC BTree library).

### Network Support
- Include UDP and TCP transport.
- Default KDC server implementation.
  - The Networking Classes in the JDK is used.
- Netty based KDC server implementation.
  - Netty is an asynchronous event-driven network application framework for rapid development of maintainable high    performance protocol servers & clients.
  - With better throughput, lower latency.

### Tools
- kinit:
  - Obtains and caches an initial ticket-granting ticket for principal.
- klist:
  - Lists the Kerby principal and tickets held in a credentials cache, or the keys held in a keytab file.
- kdcinit:
  - This is used to initialize and prepare all kinds of KDC side materials, like initializing concrete back end, setting up master keys, necessary principals (tgs, kadmin) and etc.
- kadmin:
  - Command-line interfaces to the Kerby administration system.

#### Kerby Common Projects
- kerby-asn1. A model driven ASN-1 encoding and decoding framework
- kerby-config. A unified configuration API that aims to support various configuration file formats, like XML, INI, even Java Map and Properties.
- kerby-util. Common utilities used by project.

### Dependency
- The core part is ensured to only depend on the JRE and SLF4J. Every external dependency is taken carefully and maintained separately.
- [Nimbus JOSE + JWT](http://connect2id.com/products/nimbus-jose-jwt), needed by token-provider and TokenPreauth mechanism.
- [Netty](http://netty.io/), needed by netty based KDC server.
- [Zookeeper](https://zookeeper.apache.org/), needed by zookeeper identity backend.

### How to use library
The Apache Kerby is also available as a Maven dependency.

- Kerby Client API:
```
<dependency>
    <groupId>org.apache.kerby</groupId>
    <artifactId>kerb-client-api-all</artifactId>
    <version>${kerby-version}</version>
</dependency>
```

- Kerby Server API:
```
<dependency>
    <groupId>org.apache.kerby</groupId>
    <artifactId>kerb-server-api-all</artifactId>
    <version>${kerby-version}</version>
</dependency>
```

- Kerby ASN1:
```
<dependency>
    <groupId>org.apache.kerby</groupId>
    <artifactId>kerby-asn1</artifactId>
    <version>${kerby-version}</version>
</dependency>
```

- Kerby Simple KDC:
```
<dependency>
    <groupId>org.apache.kerby</groupId>
    <artifactId>kerb-simplekdc</artifactId>
    <version>${kerby-version}/version>
</dependency>
```
- please replace the ${kerby-version} with the release version.
- Apache Kerby 1.0.0-RC1 is the latest release and recommended version for all users.

### License
Apache License V2.0

### How to contribute
- Git repo in Apache: https://git-wip-us.apache.org/repos/asf/directory-kerby.git
- Umbrella JIRA: it's tracked in the master JIRA [DIRKRB-102](https://issues.apache.org/jira/browse/DIRKRB-102), and find tasks there.
- Directory Developers List: dev@directory.apache.org [Subscribe](dev-subscribe@directory.apache.org)
- Kerby Developers List: kerby@directory.apache.org [Subscribe](kerby-subscribe@directory.apache.org)

### Downloads
- [Release 1.0.0-RC1](https://directory.apache.org/kerby/download/download-sources.html)

### News
- Sep 23, the first release 1.0.0-RC1 of Kerby was released.

### Apache Kerby 1.0.0-RC2 Release Note

105 JIRA issues were resolved and with the following Features and important changes since 1.0.0-RC1:
- 1. Anonymous PKINIT support(BETA): allows a client to obtain anonymous credentials without authenticating as any particular principal.
- 2. Finished token support:
  - Add ability to encrypt and sign using non-RSA keys;
  - Get the verify key for signed JWT token from kdc config;
  - Token issuer must be trusted as one of preconfigured issuers;
  - Add support for decrypting JWT tokens in the KDC.
- 3. PKIX CMS/X509 support.
- 4. BER encoding support.
- 5. Improved the ASN1 framework:
  - Separate Asn1 parser;
  - Support decoding of primitive but constructed encoded types;
  - Allow to define explicit and implicit fields more easily for collection types;
  - Providing an API to use some useful ASN1 functions by consolidating existing utilities
- 6. Dump support for Asn1.
  - provide an ASN1 dumping tool for troubleshooting
- 7. Separate KrbClient, KrbTokenClient, and KrbPkinitClient APIs.
