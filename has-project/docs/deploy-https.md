Deploy HTTPS
===============

## 1. Create a keystore file for each host

> keystore: the keystore file that stores the certificate.
> validity: the valid time of the certificate in days.
```
keytool -alias {hostname} -keystore {keystore} -validity {validity} -genkey
```

> The keytool will ask for more details such as the keystore password, keypassword and CN(hostname).

## 2. Export the certificate public key to a certificate file for each host
```
keytool -export -alias {hostname} -keystore {keystore} -rfc -file {cert-file}
```

## 3. Create a common truststore file (trustAll)
The truststore file contains the public key from all certificates. If you assume a 2-node cluster with node1 and node2,
login to node1 and import the truststore file for node1.
```
keytool -import -alias {hostname} -keystore {trustAll} -file {cert-file}
```

## 4. Update the common truststore file
* Move {trustAll} from node1 to node2 ({trustAll} already has the certificate entry of node1), and repeat Step 3.

* Move the updated {trustAll} from node2 to node1. Repeat these steps for each node in the cluster.
When you finish, the {trustAll} file will have the certificates from all nodes.

> Note these work could be done on the same node, just notice the hostname.

## 5. Copy {trustAll} from node1 to all of the other nodes

## 6. Validate the common truststore file
```
keytool -list -v -keystore {trustAll}
```

## 7. Edit the Configuration files
> Deploy {keystore} and {trustAll} files and config /<conf-dir>/ssl-server.conf for HAS server
```
ssl.server.keystore.location = {path to keystore}
ssl.server.keystore.password = {keystore password set in step 1}
ssl.server.keystore.keypassword = {keypassword set in step 1}
ssl.server.truststore.reload.interval = 1000
ssl.server.truststore.location = {path to trustAll}
ssl.server.truststore.password = {trustAll password set in step 2}
```

> Config /etc/has/<https_host>/ssl-client.conf for HAS client, the <https_host>
is the has server address, the same as the value configured in has-client.conf
```
ssl.client.truststore.location = {path to trustAll}
ssl.client.truststore.password = {trustAll password}
```

> Config $HADOOP_HOME/etc/hadoop/ssl-server.xml for Hadoop
```
<configuration>

<property>
  <name>ssl.server.truststore.location</name>
  <value>path to trustAll</value>
</property>

<property>
  <name>ssl.server.truststore.password</name>
  <value>trustAll password</value>
</property>

<property>
  <name>ssl.server.truststore.type</name>
  <value>jks</value>
</property>

<property>
  <name>ssl.server.truststore.reload.interval</name>
  <value>10000</value>
</property>

<property>
  <name>ssl.server.keystore.location</name>
  <value>path to keystore</value>
</property>

<property>
  <name>ssl.server.keystore.password</name>
  <value>keystore password</value>
</property>

<property>
  <name>ssl.server.keystore.keypassword</name>
  <value>keystore keypassword</value>
</property>

<property>
  <name>ssl.server.keystore.type</name>
  <value>jks</value>
</property>

</configuration>
```

> Config $HADOOP_HOME/etc/hadoop/ssl-client.xml for Hadoop
```
<configuration>

<property>
  <name>ssl.client.truststore.location</name>
  <value>patch to trustAll</value>
</property>

<property>
  <name>ssl.client.truststore.password</name>
  <value>trustAll password</value>
</property>

<property>
  <name>ssl.client.truststore.type</name>
  <value>jks</value>
</property>

<property>
  <name>ssl.client.truststore.reload.interval</name>
  <value>10000</value>
</property>

<property>
  <name>ssl.client.keystore.location</name>
  <value>path to keystore</value>
</property>

<property>
  <name>ssl.client.keystore.password</name>
  <value>keystore password</value>
</property>

<property>
  <name>ssl.client.keystore.keypassword</name>
  <value>keystore keypassword</value>
</property>

<property>
  <name>ssl.client.keystore.type</name>
  <value>jks</value>
</property>

</configuration>
```

> To make the nodes in the cluster communicate bidirectionally, deploy all the configuration files.
