Haox
====

Haox is a Java client library binding for Kerberos as an effort to catch up with latest Kerberos features. 

### Motivations  
* Provide Java client API in Kerberos protocol level to interact with a KDC server thru AS and TGS exchanges. With such API, you can write your own kinit like tool with maximum flexibility in your application.
+ Provide new Kerberos features as soon as possible that can't just be done in JRE, like PKINIT and TokenPreauth mechanisms.
+ Provide a simple KDC server that you can easily integrate into your unit tests and integration tests.
+ Least dependency, it's ensured to depend only on JRE, for easy use and maintain.

### Status
<pre>
ASN-1 (done)
Core spec types (done)
Crypto (done)
Keytab util (done)
Credential Cache (done)
AS client (going)
Preauth framework (going)
PKINIT (going)
</pre>

### The ASN-1 support
Please look at [haox-asn1](https://github.com/drankye/haox/blob/master/haox-asn1/README.md) for details.

### Kerberos Crypto and encryption types
Implementing des, des3, rc4, aes, camellia encryption and corresponding checksum types
Interoperates with MIT Kerberos and Microsoft AD
Independent with Kerberos codes in JRE, but rely on JCE

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

### Dependency
All the project including its subprojects will only depend on JRE, which ensures it can be easily embeded and integrated into your applications and systems. Currently it depends on SLF4J but that will be removed later.

##### Sub Projects
- haox-asn1. A model driven ASN-1 encoding and decoding framework
- haox-event. A pure event driven application framework aiming to construct applications of asynchronous and concurrent handlers. It includes UDP and TCP transport based on pure Java NIO and concurrency pattern.
- haox-config. A unified configuration API that aims to support various configuration file formats, like XML, JNI, CSV and Java Properties file.

### License
Apache License V2.0
