Apache Kerby
============

Apache Kerby is a Java Kerberos binding. It provides a rich, intuitive and interoperable implementation, library, KDC and various facilities that integrates PKI, OTP and token (OAuth2) as desired in modern environments such as cloud, Hadoop and mobile.

![](https://github.com/apache/directory-kerby/blob/master/docs/logo/logo.png)

### The Initiatives/Goals 
* Aims as a Java Kerberos binding, with rich and integrated facilities that integrate Kerberos, PKI and token (OAuth2) for both client and server sides.
+ Provides client APIs at the Kerberos protocol level to interact with a KDC server through AS and TGS exchanges.
+ Provides a standalone KDC server that supports various identity back ends including memory based, Json file based, LDAP backed and even Zookeeper backed.
+ Provides an embedded KDC server that applications can easily integrate into products, unit tests or integration tests.
+ Supports FAST/Preauthentication framework to allow popular and useful authentication mechanisms.
+ Supports PKINIT mechanism to allow clients to request tickets using x509 certificate credentials.
+ Supports Token Preauth mechanism to allow clients to request tickets using JWT tokens.
+ Supports OTP mechanism to allow clients to request tickets using One Time Password.
+ Provides support for JAAS, GSSAPI and SASL frameworks that applications can leverage.
+ Minimal dependencies, the core part is ensured to depend only on JRE and SLF4J, for easy use and maintenance.

### KrbClient APIs
* Initiate a KrbClient
<pre>
KrbClient krbClient = new KrbClient(kdcHost, kdcPort);
</pre>
* Request a TGT with user plain password credential
<pre>
krbClient.requestTgtTicket(principal, password);
</pre>
* Request a TGT with a keytab file
<pre>
krbClient.requestTgtTicket(principal, keytab);
</pre>
* Request a TGT with user x509 certificate credential
<pre>
krbClient.requestTgtTicket(principal, certificate);
</pre>
* Request a TGT with user token credential
<pre>
krbClient.requestTgtTicket(principal, kerbToken);
</pre>
* Request a service ticket with user TGT credential for a server
<pre>
krbClient.requestServiceTicket(tgt, serverPrincipal);
</pre>
* Request a service ticket with user AccessToken credential for a server
<pre>
krbClient.requestServiceTicket(accessToken, serverPrincipal);
</pre>

### ASN-1 support
Please look at [kerby-asn1](kerby-asn1/) for details.

### Kerberos Crypto and Encryption Types
Implementing des, des3, rc4, aes, camellia encryption and corresponding checksum types
Interoperates with MIT Kerberos and Microsoft AD
Independent of Kerberos code in JRE, but rely on JCE

| Encryption Type | Description |
| --------------- | ----------- |
| des-cbc-crc | DES cbc mode with CRC-32 (weak) |
| des-cbc-md4 | DES cbc mode with RSA-MD4 (weak) |
| des-cbc-md5 |	DES cbc mode with RSA-MD5 (weak) |
| des3-cbc-sha1 des3-hmac-sha1 des3-cbc-sha1-kd |	Triple DES cbc mode with HMAC/sha1 |
| des-hmac-sha1 |	DES with HMAC/sha1 (weak) |
| aes256-cts-hmac-sha1-96 aes256-cts AES-256 	| CTS mode with 96-bit SHA-1 HMAC |
| aes128-cts-hmac-sha1-96 aes128-cts AES-128 	| CTS mode with 96-bit SHA-1 HMAC |
| arcfour-hmac rc4-hmac arcfour-hmac-md5 |	RC4 with HMAC/MD5 |
| arcfour-hmac-exp rc4-hmac-exp arcfour-hmac-md5-exp |	Exportable RC4 with HMAC/MD5 (weak) |
| camellia256-cts-cmac camellia256-cts |	Camellia-256 CTS mode with CMAC |
| camellia128-cts-cmac camellia128-cts |	Camellia-128 CTS mode with CMAC |
| des |	The DES family: des-cbc-crc, des-cbc-md5, and des-cbc-md4 (weak) |
| des3 |	The triple DES family: des3-cbc-sha1 |
| aes |	The AES family: aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96 |
| rc4 |	The RC4 family: arcfour-hmac |
| camellia | The Camellia family: camellia256-cts-cmac and camellia128-cts-cmac |

### How to play with the standalone KDC
 [Kerby KDC](kerby-dist/README.md)

#### Kerby Lib Projects
- kerby-asn1. A model driven ASN-1 encoding and decoding framework
- kerby-event. A pure event driven application framework aiming to construct applications of asynchronous and concurrent handlers. It includes UDP and TCP transports based on pure Java NIO and concurrency pattern.
- kerby-config. A unified configuration API that aims to support various configuration file formats, like XML, INI, even Java Map and Properties.

### Dependency
- The core part is ensured to only depend on the JRE and SLF4J. Every external dependency is taken carefully and maintained separately.
- [Not-Yet-Commons-SSL](http://juliusdavies.ca/not-yet-commons-ssl-0.3.9/), required by pki-provider and PKINIT mechanism.
- [Nimbus JOSE + JWT](http://connect2id.com/products/nimbus-jose-jwt), needed by token-provider and TokenPreauth mechanism.

### License
Apache License V2.0

### How to contribute
- Git repo in Apache: [Source codes](https://git-wip-us.apache.org/repos/asf/directory-kerby.git)
- Umbrella JIRA: it's tracked in the master JIRA [DIRKRB-102](https://issues.apache.org/jira/browse/DIRKRB-102), and find tasks there.
