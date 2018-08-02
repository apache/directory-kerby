
MySQL Plugin
===============

## Install MySQL

Please refer to [install mysql](https://dev.mysql.com/doc/refman/5.7/en/linux-installation.html).

## Prepare user infomation in MySQL

### Create database "has" and create table "has_user"
```
mysql> create database has;
mysql> use has;
mysql> CREATE TABLE has_user(user_name VARCHAR(100), pass_word VARCHAR(100));
```

### Insert user into table
Example, username is "hdfs", password is "test":
```
mysql> INSERT INTO has_user VALUES ('hdfs', 'test');
```

## Config HAS server 
Example:
```
export mysqlUrl=jdbc:mysql://127.0.0.1:3306/has
export mysqlUser=root
export mysqlPasswd=123456
```

## Config client
Example:
```
export userName=hdfs
export password=test
```
