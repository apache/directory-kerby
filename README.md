Haox
====

Haox is a Java client library binding for Kerberos as an effort to catch up with latest Kerberos features. It will also provide a simple KDC
server implementation for unit test and integration usages for Kerberized system and application development.

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

### haox-asn1
Look at [haox-asn1](https://github.com/drankye/haox/blob/master/haox-asn1/README.md)

### kerb-crypto
Implementing des, des3, rc4, aes, camellia encryption and corresponding checksum types
Interoperates with MIT Kerberos
Independent with Kerberos codes in JRE, but rely on JCE

### Dependency
It surely only depends on JRE. Currently it depends on SLF4J but that will be removed.

### License
Apache License V2.0
