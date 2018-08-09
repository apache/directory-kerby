<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

Enable Spark
===============

## 1. Apply the [patch](https://github.com/apache/directory-kerby/blob/has-project/has/supports/hadoop/hadoop-2.7.2.patch) to hadoop-2.7.2 source code
```
git apply hadoop-2.7.2.patch
```

## 2. Install
```
mvn clean install -DskipTests
```

## 3. Apply the patch to spark-v2.0.0 source code
```
git apply spark-v2.0.0.patch
```

## 4. Build
```
./build/mvn -Pyarn -Phadoop-2.7 -Dhadoop.version=2.7.2 -DskipTests clean package
```

## 5. Update spark-env.sh
```
SPARK_HISTORY_OPTS=-Dspark.history.kerberos.enabled=true \
-Dspark.history.kerberos.principal=<spark/_HOST@HADOOP.COM> \
-Dspark.history.kerberos.keytab=<keytab>
```

> Note "_HOST" should be replaced with the specific hostname.

## 6. Spark-submit job
> YARN mode supported only
```
/bin/spark-submit \
  --use-has \
  --class <main-class>
  --master <master-url> \
  --deploy-mode <deploy-mode> \
  --conf <key>=<value> \
  ... # other options
  <application-jar> \
  <application-arguments>
```
