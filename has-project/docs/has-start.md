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

### Configure HAS KDC:

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
sh bin/kdcinit.sh <conf_dir>
HasInitTool: start
HasInitTool: exit
```
