Enable Oozie
===============

## 1. Update oozie-site.xml
add the following properties:
```
<property>
  <name>oozie.service.AuthorizationService.security.enabled</name>
  <value>true</value>
  <description>Specifies whether security (user name/admin role) is enabled or not.
   If it is disabled any user can manage the Oozie system and manage any job.</description>
</property>

<property>
  <name>oozie.service.HadoopAccessorService.kerberos.enabled</name>
  <value>true</value>
</property>

<property>
  <name>local.realm</name>
  <value>HADOOP.COM</value>
  <description>HAS Realm.</description>
</property>

<property>
  <name>oozie.service.HadoopAccessorService.keytab.file</name>
  <value>/etc/oozie/conf/oozie.keytab</value>
  <description>The keytab of the Oozie service.</description>
</property>

<property>
  <name>oozie.service.HadoopAccessorService.kerberos.principal</name>
  <value>oozie/_HOST@HADOOP.COM</value>
  <description>Principal of Oozie service.</description>
</property>

<property>
  <name>oozie.authentication.kerberos.principal</name>
  <value>HTTP/_HOST@HADOOP.COM</value>
  <description>Must use the hostname of the Oozie Server.</description>
</property>

<property>
  <name>oozie.authentication.kerberos.keytab</name>
  <value>/etc/hadoop/conf/hdfs.keytab</value>
  <description>Location of the hdfs keytab file which contains the HTTP principal.</description>
</property>

<property>
  <name>oozie.authentication.type</name>
  <value>kerberos</value>
  <description></description>
</property>

<property>
  <name>oozie.authentication.kerberos.name.rules</name>
  <value>DEFAULT</value>
  <description>The mapping from principal names to local service user names.</description>
</property>
```

> Note "_HOST" should be replaced with the specific hostname.

## 2. Start oozie
```
bin/oozied.sh start
```

## 3. Using kinit to get the credential cache

## 4. Using the Oozie command line tool check the status of Oozie:
```
bin/oozie.sh admin -oozie http://<host>:11000/oozie -status
```

return:
```
System mode: NORMAL
```

## 5. Using the curl to check the status of Oozie:
```
curl -i --negotiate -u : "http://<host>:11000/oozie/v1/admin/status"
```

return:
```
HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: Negotiate
Set-Cookie: hadoop.auth=; Path=/; Expires=Thu, 01-Jan-1970 00:00:00 GMT; HttpOnly
Content-Type: text/html;charset=utf-8
Content-Length: 997
Date: Wed, 28 Jun 2017 03:45:28 GMT

HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
WWW-Authenticate: Negotiate YGoGCSqGSIb3EgECAgIAb1swWaADAgEFoQMCAQ+iTTBLoAMCARGiRARCzCqLa8uqKUk6UlJfN02KC79DDFpStTBieqHBfhYEm6S1GyrP29Sr3hC4lYl4U42NFSwTb/ySjqu3EpOhBJo5Bg4h
Set-Cookie: hadoop.auth="u=oozie&p=oozie/_HOST@EXAMPLE.COM&t=kerberos&e=1498657528799&s=waJ0DZ80kcA2Gc9pYMNIGsIAC5Y="; Path=/; Expires=Wed, 28-Jun-2017 13:45:28 GMT; HttpOnly
Content-Type: application/json;charset=UTF-8
Content-Length: 23
Date: Wed, 28 Jun 2017 03:45:28 GMT

{"systemMode":"NORMAL"}
```
