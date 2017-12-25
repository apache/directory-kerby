How to start
================

## 1. Install

### Download HAS source code:
```
git clone https://github.com/apache/directory-kerby.git -b has-project
```

### Apply the example plugin patch
Download from https://github.com/plusplusjiajia/HAS-plugins/blob/master/AWS.patch

### Install HAS:
```
cd directory-kerby/has
mvn clean install
```

## 2. Start and configure HAS server

### Deploy https
Please look at [How to deploy https](https://github.com/apache/directory-kerby/blob/has-project/has/doc/deploy-https.md) for details.

### Configure has-server.conf in <conf_dir>:
An example of has-server.conf:
```
[HAS]
  https_host = localhost
  https_port = 8092
  filter_auth_type = kerberos
  
[PLUGIN]
  auth_type = RAM
```

### Start HAS server:
```
cd HAS/has-dist
sh bin/start-has.sh <conf_dir> <work_dir>
```

also:
```
export HAS_CONF_DIR=<conf_dir>
export HAS_WORK_DIR=<work_dir>
cd HAS/has-dist
sh bin/start-has.sh
```

Root privileges required if https_port or KDC port numbers range from 0 to 1023.

### Configure HAS plugin:
```
cd HAS/has-dist
// Proxy needed to be removed if it exists
unset https_proxy
// Start KDC init tool
sh bin/kdcinit.sh <conf_dir>
// Also: sh bin/kdcinit.sh, if HAS_CONF_DIR environment variable has been set.
// Plugin_name example: RAM
KdcInitTool: set_plugin <plugin_name>
KdcInitTool: exit
```

### Configure HAS backend:
```
cd HAS/has-dist
// Start KDC init tool
sh bin/kdcinit.sh <conf_dir>
// An example of json backend:
KdcInitTool: config_kdcBackend json /tmp/has/jsonbackend
// An example of mysql backend:
KdcInitTool: config_kdcBackend mysql jdbc:mysql://127.0.0.1:3306/mysqlbackend root passwd
KdcInitTool: exit
```
For mysql backend, please refer to [How to use mysql backend](https://github.com/apache/directory-kerby/blob/has-project/has/doc/mysql-backend.md) for details.

### Configure HAS KDC:
```
cd HAS/has-dist
// Start KDC init tool
sh bin/kdcinit.sh <conf_dir>
// An example of configure HAS KDC:
KdcInitTool: config_kdc localhost 88 HADOOP.COM
KdcInitTool: exit
```
Please make sure the following configuration files exist in the conf directory:
has-server.conf backend.conf kdc.conf

### Start HAS KDC server:
```
cd HAS/has-dist
// Start KDC init tool
sh bin/kdcinit.sh <conf_dir>
KdcInitTool: start
KdcInitTool: exit
```

### Init HAS server:
```
cd HAS/has-dist
// Start KDC init tool
sh bin/kdcinit.sh <conf_dir>
KdcInitTool: init
KdcInitTool: exit
```

### Deploy http spnego
Please look at [How to deploy http spnego](https://github.com/apache/directory-kerby/blob/has-project/has/doc/deploy-spnego.md) for details.
Please restart the HAS server

```
cd HAS/has-dist
sh bin/stop-has.sh

cd HAS/has-dist
sh bin/start-has.sh <conf_dir> <work_dir>

cd HAS/has-dist
sh bin/kdcinit.sh <conf_dir>
KdcInitTool: start
KdcInitTool: exit
```

### Get krb5.conf:
```
cd HAS/has-dist
// Start KDC init tool:
sh bin/kdcinit.sh <conf_dir>
// Get krb5.conf, and put it to /etc:
KdcInitTool: getkrb5 -p /etc
KdcInitTool: exit
```

### Get has-client.conf:
```
cd HAS/has-dist
// Start KDC init tool
sh bin/kdcinit.sh <conf_dir>
// Get has-client.conf, and put it to /etc/has:
KdcInitTool: gethas -p /etc/has
KdcInitTool: exit
```

## 3. Prepare for Hadoop

### Create service principals:
```
cd HAS/has-dist
echo { \
    HOSTS: [ \
       {"name":"<host>","hostRoles":"<role>,..., <role>"\}, \
       ...
       {"name":"<host>","hostRoles":"<role>,...,<role>"\} \
    ] \
\} > hosts.txt
// Start local hadmin tool
sh bin/hadmin-local.sh <conf_dir> -k <keytab>
// Also: sh bin/hadmin-local.sh -k <keytab>, if HAS_CONF_DIR environment variable has been set.
// Also you can use remote hadmin tool, admin.keytab file needed to be placed in /etc/has
sh bin/hadmin-remote.sh <conf_dir>
// Also: sh bin/hadmin-remote.sh, if HAS_CONF_DIR environment variable has been set.
HadminLocalTool.local: creprincs hosts.txt
HadminLocalTool.local: exit
```
The admin.keytab file is created by the kdcinit. In local and remote hadmin tool, you can type "?" for help.

### Get hostRoles list:
```
cd HAS/has-dist
// Start local or remote hadmin tool
sh bin/hadmin-local.sh(bin/hadmin-remote.sh) <conf_dir> -k <keytab>
HadminLocalTool.local: hostroles
HadminLocalTool.local: exit
```

### Export service keytabs:
```
cd HAS/has-dist
// Start local or remote hadmin tool
sh bin/hadmin-local.sh(bin/hadmin-remote.sh) <conf_dir> -k <keytab>
// An example of exporting keytabs of localhost(hostname):
HadminLocalTool.local: expkeytabs localhost
HadminLocalTool.local: exit
```
