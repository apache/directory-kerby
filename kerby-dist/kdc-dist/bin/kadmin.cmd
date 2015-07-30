set DEBUG=
set args=%*
for %%a in (%*) do (
  if -D == %%a (
    set DEBUG=-Xdebug -Xrunjdwp:transport=dt_socket,address=8001,server=y,suspend=n
    set args=%args:-D=%
  )
)

java %DEBUG% ^
-classpath lib\* ^
-DKERBY_LOGFILE=kerby-kdc ^
org.apache.kerby.kerberos.tool.kadmin.KadminTool %args%
