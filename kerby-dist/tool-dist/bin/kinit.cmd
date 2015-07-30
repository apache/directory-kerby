set DEBUG=
set args=%*
for %%a in (%*) do (
  if -D == %%a (
    set DEBUG=-Xdebug -Xrunjdwp:transport=dt_socket,address=8002,server=y,suspend=n
    set args=%args:-D=%
  )
)

java %DEBUG% ^
-classpath lib\* ^
-DKERBY_LOGFILE=kinit ^
org.apache.kerby.kerberos.tool.kinit.KinitTool %args%
