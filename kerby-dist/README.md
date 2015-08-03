Kerby-dist
============

The distribution of Kerby.

### To run with a standalone kdc server, kdcinit, kadmin, kinit and klist

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

* 3. Run kadmin to add principals:
```
cd kerby-dist/kdc-dist
sh bin/kadmin.sh [server-conf-dir] -k [keytab]
```

  In kadmin, you can type "?" for help. For now, the kadmin only supports to add principals to json-backend. (Working in progress).

* 4. Start kerby-kdc-server:
```
cd kerby-dist/kdc-dist
sh bin/start-kdc.sh –start [server-conf-dir] [work-dir]
```

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
  And if you don't specify [client -conf-dir] in step 5, it will be set as /etc/, there should be krb5.conf.

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
```

