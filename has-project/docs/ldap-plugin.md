LDAP Plugin
===============

## Install and start [ApacheDS](https://directory.apache.org/apacheds/)

Please refer to [install ApacheDS](https://directory.apache.org/apacheds/basic-ug/1.3-installing-and-starting.html).

## Prepare user infomation in ApacheDS

### Add user partition
Please refer to [Add Partition](https://directory.apache.org/apacheds/basic-ug/1.4.3-adding-partition.html) .
Example:
```
Partition Type: JDBM
ID: has
Suffix: ou=has,dc=kerby,dc=com
```

### Insert user into LDAP server

Following is an example of the ldif file to be imported, username is "hdfs", password is "test":
```
dn: cn=hdfs,ou=has,dc=kerby,dc=com
objectclass: inetOrgPerson
objectclass: organizationalPerson
objectclass: person
objectclass: top
cn: HDFS
description: This is user hdfs.
sn: hello
mail: hello@apache.org
userpassword: test
```

## Config /etc/has/ldap-server.ini in HAS server host
Example:
```
  [ users ]
      user_filter=objectclass=*
      user_name_attr=cn

  [ ldap ]
       base_dn=ou=has,dc=kerby,dc=com
       bind_dn=uid=admin,ou=system
       bind_password=secret
       host=127.0.0.1
       port=10389
```

## Config client
Example:
```
export LDAP_USER=hdfs
export LDAP_PWD=test
```
