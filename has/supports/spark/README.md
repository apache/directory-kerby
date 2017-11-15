Enable Spark
===============

## 1. Update spark-env.sh
```
SPARK_HISTORY_OPTS=-Dspark.history.kerberos.enabled=true \
-Dspark.history.kerberos.principal=<spark/_HOST@HADOOP.COM> \
-Dspark.history.kerberos.keytab=<keytab>
```

> Note "_HOST" should be replaced with the specific hostname.

## 2. Spark-submit job
> YARN mode supported only
```
/bin/spark-submit \
  --keytab <keytab> \ 
  --principal <spark/hostname@HADOOP.COM> \
  --class <main-class>
  --master <master-url> \
  --deploy-mode <deploy-mode> \
  --conf <key>=<value> \
  ... # other options
  <application-jar> \
  <application-arguments>
```
