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
