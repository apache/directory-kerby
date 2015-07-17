java -Xdebug -Xrunjdwp:transport=dt_socket,address=8001,server=y,suspend=n -classpath ^
lib\* ^
-DKERBY_LOGFILE=kerby-kdc ^
org.apache.kerby.kerberos.tool.kadmin.KadminTool %*
