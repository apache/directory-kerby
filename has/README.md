# Hadoop Authentication Service (HAS)
A dedicated Hadoop Authentication Server to support various authentication mechanisms other than just Kerberos. In its core it leverages a Kerby KDC developed by [Apache Kerby](https://github.com/apache/directory-kerby), a sub project of [Apache Directory](http://directory.apache.org).

# High level considerations
* Hadoop services are still strongly authenticated by Kerberos, as Kerberos is the only means so far to enable Hadoop security.
* Hadoop users can remain to use their familiar login methods.
* Security admins won't have to migrate and sync up their user accounts to Kerberos back and forth.
* New authentication mechanism can be customized and plugined.

# Architecture
![](https://github.com/apache/directory-kerby/blob/has-project/has/doc/has-overall.png)

# Design
Assuming existing users are stored in a SQL database (like MySQL), the detailed design and workflow may go like the following:
![](https://github.com/apache/directory-kerby/blob/has-project/has/doc/has-design.png)


# New mechanism plugin API

## HAS client plugin HasClientPlugin:

```Java
// Get the login module type ID, used to distinguish this module from others. 
// Should correspond to the server side module.
String getLoginType()

// Perform all the client side login logics, the results wrapped in an AuthToken, 
// will be validated by HAS server.
AuthToken login(Conf loginConf) throws HasLoginException
```

## HAS server plugin HasServerPlugin:

```Java
// Get the login module type ID, used to distinguish this module from others. 
// Should correspond to the client side module.
String getLoginType()

// Perform all the server side authentication logics, the results wrapped in an AuthToken, 
// will be used to exchange a Kerberos ticket.
AuthToken authenticate(AuthToken userToken) throws HasAuthenException
```

## REST API
Please look at [REST API](https://github.com/apache/directory-kerby/blob/has-project/has/doc/rest-api.md) for details.

## How to start
Please look at [How to start](https://github.com/apache/directory-kerby/blob/has-project/has/doc/has-start.md) for details.

## High Availability
Please look at [High Availability](https://github.com/apache/directory-kerby/blob/has-project/has/doc/has-ha.md) for details.

## Cross Realm
Please look at [How to setup cross-realm](https://github.com/apache/directory-kerby/blob/has-project/has/doc/cross-realm.md) for details.

## Enable Hadoop ecosystem components

* [Enable Hadoop](https://github.com/apache/directory-kerby/blob/has-project/has/supports/hadoop/README.md)

* [Enable Zookeeper](https://github.com/apache/directory-kerby/blob/has-project/has/supports/zookeeper/README.md)

* [Enable HBase](https://github.com/apache/directory-kerby/blob/has-project/has/supports/hbase/README.md)

* [Enable Hive](https://github.com/apache/directory-kerby/blob/has-project/has/supports/hive/README.md)

* [Enable Phoenix](https://github.com/apache/directory-kerby/blob/has-project/has/supports/phoenix/README.md)

* [Enable Thrift](https://github.com/apache/directory-kerby/blob/has-project/has/supports/thrift/README.md)

* [Enable Spark](https://github.com/apache/directory-kerby/blob/has-project/has/supports/spark/README.md)

* [Enable Oozie](https://github.com/apache/directory-kerby/blob/has-project/has/supports/oozie/README.md)

* [Enable Presto](https://github.com/apache/directory-kerby/blob/has-project/has/supports/presto/README.md)

## List of supported Hadoop ecosystem components

|   Big Data Components   |           Supported         |   Rebuild Required   |   Configuring Required   |
|:-----------------------:|:---------------------------:|:--------------------:|:------------------------:|
| Hadoop                  | Yes                         | Yes                  | Yes                      |
| Zookeeper               | Yes                         | Yes                  | Yes                      |
| HBase                   | Yes                         | Yes                  | Yes                      |
| Hive                    | Yes                         | No                   | Yes                      |
| Phoenix                 | Yes                         | No                   | Yes                      |
| Thrift                  | Yes                         | No                   | Yes                      |
| Spark                   | Yes                         | No                   | Yes                      |
| Oozie                   | Yes                         | No                   | Yes                      |
| Presto                  | Yes (0.148 and later)       | No                   | Yes                      |
| Pig                     | Yes                         | No                   | No                       |
| Sqoop                   | Yes                         | No                   | No                       |

## Performance test report
Please look at [Performance test report](https://github.com/apache/directory-kerby/blob/has-project/has/doc/performance-report.md) for details.
