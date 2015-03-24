Kerby-dist
============

The distribution of Kerby.

### To run with a standalone kdc server, kinit and kadmin

* Generate libraries for distribution:
```
mvn package -Pdist
```

* Run kadmin to add principals:
```
sh kerby-dist/tool-dist/bin/kadmin.sh [server-conf-dir]
```

  In kadmin, you can type "?" for help. For now, the kadmin only supports to add principals to json-backend. (Working in progress).

* Start kerby-kdc-server:
```
sh kerby-dist/kdc-dist/bin/start-kdc.sh –start [server-conf-dir] [work-dir]
```

* Run kinit:
```
sh kerby-dist/tool-dist/bin/kinit.sh [principal-name]
```

  If you don't specify [server-conf-dir] in step 2 or 3, it will be set as /etc/kerby. In [server-conf-dir], there should be kdc.conf, backend.conf. And in /etc/, there should be krb5.conf.

An example of kdc.conf:
```
[kdcdefaults]
    kdc_host = localhost
    kdc_tcp_port = 8015
    kdc_realm = TEST.COM
```
An example of backend.conf:
```
kdc_identity_backend = org.apache.kerby.kerberos.kdc.identitybackend.JsonIdentityBackend
backend.json.file = /tmp/kerby/jsonbackend
```

An example of krb5.conf:
```
[libdefaults]
    kdc_realm=TEST.COM
```

