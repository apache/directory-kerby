How to install kerby-server?

1. Set the absolute path of the directory:kerby-dist\kerby-server in kerby-dist\conf\wrapper.conf:
Change the value of wrapper.working.dir.(in the line 28)
e.g. 
wrapper.working.dir=C:\\Users\\hazel\\workspace\\directory-kerberos\\kerby-dist\\kerby-server\\
or
wrapper.working.dir=/hazel/workspace/directory-kerberos/kerby-dist/kerby-server

2.Everytime you want to reinstall, just run:
mvn package -Pdependency
mvn antrun:run

3.Then you can run the service by
bat/runConsole.bat,
bat/installService.bat,
bat/startService.bat,
bat/stopService.bat,
bat/uninstallService.bat in Windows. And bin/... in Linux.