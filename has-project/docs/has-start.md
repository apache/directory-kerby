Getting Started
================

## 1. Install

### Download Kerby source code:
```
git clone https://github.com/apache/directory-kerby.git
```

### Install HAS:
```
cd directory-kerby
mvn clean install -Pdist -DskipTests
```

## 2. Start and configure HAS server

### Deploy https
Please look at [How to deploy https](https://github.com/apache/directory-kerby/blob/trunk/has-project/docs/deploy-https.md) for details.

### Configure has-server.conf in <conf_dir>:
An example of has-server.conf:
```
[HAS]
  https_host = localhost
  https_port = 8092
  filter_auth_type = kerberos

[PLUGIN]
  auth_type = MySQL
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
cd kerby-dist/has-dist
// Proxy needed to be removed if it exists
unset https_proxy
// Start HAS init tool
sh bin/has-init.sh <conf_dir>
// Also: sh bin/has-init.sh, if HAS_CONF_DIR environment variable has been set.
// Plugin_name example: MySQL
HasInitTool: set_plugin <plugin_name>
HasInitTool: exit
```

### Configure HAS backend:
```
cd kerby-dist/has-dist
// Start HAS init tool
sh bin/has-init.sh <conf_dir>
// An example of json backend:
HasInitTool: config_kdcBackend json /tmp/has/jsonbackend
// An example of mysql backend:
HasInitTool: config_kdcBackend mysql jdbc:mysql://127.0.0.1:3306/mysqlbackend root passwd
HasInitTool: exit
```

### Configure HAS KDC:
```
cd kerby-dist/has-dist
// Start HAS init tool
sh bin/has-init.sh <conf_dir>
// An example of configure HAS KDC:
HasInitTool: config_kdc localhost 88 HADOOP.COM
HasInitTool: exit
```
Please make sure the following configuration files exist in the conf directory:
has-server.conf backend.conf kdc.conf

### Start HAS KDC server:
```
cd kerby-dist/has-dist
// Start HAS init tool
sh bin/has-init.sh <conf_dir>
HasInitTool: start
HasInitTool: exit
```

### Init HAS server:
```
cd kerby-dist/has-dist
// Start HAS init tool
sh bin/has-init.sh <conf_dir>
HasInitTool: init
HasInitTool: exit
```

### Deploy http spnego
Please look at [How to deploy http spnego](https://github.com/apache/directory-kerby/blob/trunk/has-project/docs/deploy-spnego.md) for details.
Please restart the HAS server

```
cd kerby-dist/has-dist
sh bin/stop-has.sh

cd kerby-dist/has-dist
sh bin/start-has.sh <conf_dir> <work_dir>

cd kerby-dist/has-dist
sh bin/has-init.sh <conf_dir>
HasInitTool: start
HasInitTool: exit
```

### Get and deploy krb5.conf:
```
cd kerby-dist/has-dist
// Start HAS init tool:
sh bin/has-init.sh <conf_dir>
// Get krb5.conf, and put it to /etc:
HasInitTool: getkrb5 -p /etc
HasInitTool: exit
```

### Get and deploy has-client.conf:
```
cd kerby-dist/has-dist
// Start HAS init tool
sh bin/has-init.sh <conf_dir>
// Get has-client.conf, and put it to /etc/has:
HasInitTool: gethas -p /etc/has
HasInitTool: exit
```

## 3. Prepare for Hadoop
There are two ways to create and deploy corresponding keytabs of Hadoop.

### a. Create and deploy keytabs manually
#### Create service principals:
```
cd kerby-dist/has-dist
echo { \
    HOSTS: [ \
       {"name":"<host>","hostRoles":"<role>,..., <role>"\}, \
       ...
       {"name":"<host>","hostRoles":"<role>,...,<role>"\} \
    ] \
\} > hosts.txt
// Start local hadmin tool
sh bin/admin-local.sh <conf_dir> -k <keytab>
// Also: sh bin/admin-local.sh -k <keytab>, if HAS_CONF_DIR environment variable has been set.
// Also you can use remote admin tool, admin.keytab file needed to be placed in /etc/has
sh bin/admin-remote.sh <conf_dir>
// Also: sh bin/admin-remote.sh, if HAS_CONF_DIR environment variable has been set.
HadminLocalTool.local: creprincs hosts.txt
HadminLocalTool.local: exit
```
The admin.keytab file is created by the kdcinit. In local and remote hadmin tool, you can type "?" for help.

#### Get hostRoles list:
```
cd kerby-dist/has-dist
// Start local or remote hadmin tool
sh bin/admin-local.sh(bin/admin-remote.sh) <conf_dir> -k <keytab>
HadminLocalTool.local: hostroles
HadminLocalTool.local: exit
```

#### Export service keytabs:
```
cd kerby-dist/has-dist
// Start local or remote hadmin tool
sh bin/admin-local.sh(bin/admin-remote.sh) <conf_dir> -k <keytab>
// An example of exporting keytabs of localhost(hostname):
HadminLocalTool.local: expkeytabs localhost
HadminLocalTool.local: exit
```

### b. One step to create service principals, export keytabs and deploy keytabs:
```
cd kerby-dist/has-dist
echo { \
    HOSTS: [ \
       {"name":"<host>","hostRoles":"<role>,..., <role>"\}, \
       ...
       {"name":"<host>","hostRoles":"<role>,...,<role>"\} \
    ] \
\} > hosts.txt

// Start local hadmin tool
sh bin/admin-local.sh <conf_dir> -k <keytab>

// deploy_keytabs [HostRoles-File] [Where-to-Deploy] [SSH-Port] [UserName] [Password]
// Where-to-Deploy: The place to store the keytabs
// UserName: The host user name
// Password: The host password
// All the hosts with the same user and password
HadminLocalTool.local: deploy_keytabs hosts.txt 22 /etc/has/ username password
HadminLocalTool.local: exit
```
Note: The admin.keytab file is created by the `has-init`. In local hadmin tool, you can type "?" for help.
