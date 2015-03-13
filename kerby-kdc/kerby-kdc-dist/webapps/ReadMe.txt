NOTE: this sample is currently not maintained
It will however give you an idea how to use YAJSW for remote configuraiton

This is a sample of how to enable YAJSW java web start booter and network loading of your application

copy <yajsw> zip file to webapps/yajsw/yajsw.zip.
copy your application zip file to webapps/yajsw/.
copy your yajsw network configuration file to webapps/yajsw/wrapper.conf

start your web server (for example tomcat)
in your browser call the url: http://mysite/yajsw/yajsw.jnlp

A running example is available on :

http://yajsw.sourceforge.net/yajsw/yajsw.jnlp


wrapper.jnlp specifies the YAJSW java web start booter
wrapper.conf is the configuration for wrapping tomcat

NOTE: using zip over http is just an example.
given that YAJSW uses apache commons VFS your application you may use any of the supported transports
(webdav, http, https, ftp, sftp, ...) to access the application and the application configuration.

