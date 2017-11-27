High Availability Using MySQL Backend
========================================

The HAS High Availability feature implemented by providing the option of running two redundant HAS servers. 

## Deployment

### 1. Configure has-server.conf

The two redundant HAS servers must have same https ports. Below are examples:

* has-server.conf of HAS server on emr-header-1:
```
[HAS]
  https_host = emr-header-1
  https_port = 8092
  filter_auth_type = kerberos
  enable_conf = true

[PLUGIN]
  auth_type = RAM
```

* has-server.conf of HAS server on emr-worker-1:
```
[HAS]
  https_host = emr-worker-1
  https_port = 8092
  filter_auth_type = kerberos
  enable_conf = true

[PLUGIN]
  auth_type = RAM
```

### 2. Start HAS servers

### 3. Configure HAS backend

The two redundant HAS servers must use **mysql** backend, and have same *mysql_url*, *mysql_user* and *mysql_password*.

Please look at [How to use mysql backend](https://github.com/apache/directory-kerby/blob/has-project/has/doc/mysql-backend.md) for mysql backend configuration.

### 4. Configure HAS KDC

The two redundant HAS servers must have same ports and realms.

### 5. Start and init HAS KDC servers

> After doing init on either HAS server, the other one has been initialized too.
>
> Please keep the shared admin.keytab safely.

### 6. Reexport has-client.conf for HAS web server HA

```
cd HAS/has-dist
// Start KDC init tool
sh bin/kdcinit.sh <conf_dir>
// Get has-client.conf, and put it to /etc/has:
KdcInitTool: gethas -p /etc/has
KdcInitTool: exit
```

You will get has-client.conf like the following:
```
[HAS]
  https_host = emr-header-1,emr-worker-1
  https_port = 8092
  filter_auth_type = kerberos
  enable_conf = true

[PLUGIN]
  auth_type = RAM
```

Hadoop user can use HAS HA feature by updating **core-site.xml** without Reexport has-client.conf.
add the following properties:
```
<property>
   <name>hadoop.security.has</name>
   <value>https://emr-header-1:8092/has/v1?auth_type=RAM;https://emr-worker-1:8092/has/v1?auth_type=RAM</value>
</property>
```

### 7. Reexport krb5.conf for HAS KDC HA

```
cd HAS/has-dist
// Start KDC init tool:
sh bin/kdcinit.sh <conf_dir>
// Get krb5.conf, and put it to /etc:
KdcInitTool: getkrb5 -p /etc
KdcInitTool: exit
```

You will get krb5.conf like the following:
```
[libdefaults]
    kdc_realm = HADOOP.COM
    default_realm = HADOOP.COM
    udp_preference_limit = 4096
    kdc_tcp_port = 88
    kdc_udp_port = 88

[realms]
    HADOOP.COM = {
        kdc = localhost:88
        kdc = localhost:88
    }
```

## Verification

You can use login-test tool to verify:

### 1. Update hadmin.conf in <conf_dir>

### 2. Run login-test tool
```
cd HAS/has-dist
// Use tgt to login
sh bin/login-test.sh tgt <conf_dir>
```
