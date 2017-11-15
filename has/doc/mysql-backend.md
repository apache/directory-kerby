MySQL Backend
===============

## Install MySQL

Please refer to [install mysql](https://dev.mysql.com/doc/refman/5.7/en/linux-installation.html).

## Config backend
```
// Url: jdbc url of mysql database; mysqlbackend: name of has mysql backend database; username: mysql user name; password: mysql password
cd HAS/has-dist
sh bin/kdcinit.sh conf
KdcInitTool: config_kdcBackend mysql jdbc:mysql://127.0.0.1:3306/mysqlbackend?createDatabaseIfNotExist=true root passwd
KdcInitTool: exit
```

## Config kdc
```
cd HAS/has-dist
sh bin/kdcinit.sh conf
KdcInitTool: config_kdc localhost 88 HADOOP.COM
KdcInitTool: exit
```
