REST API
==========

## Config API        AuthType:HTTPS

### Set HAS Plugin
* Submit a HTTP PUT request.
```
    https://<host>:<port>/has/v1/conf/setplugin?plugin=<plugin>
```
Example:
```
    put https://<host>:<port>/has/v1/conf/setplugin?plugin=RAM
    Code:200
    Content-Type:text/plain
    Content:
        HAS plugin set successfully.
```
### Configure HAS backend
* Submit a HTTP PUT request.
```
    https://<host>:<port>/has/v1/conf/configkdcbackend?backendType=<backendType>
        [&dir=<dir>] [&url=<url>] [&user=<user>] [&password=<password>]
```
Example:
```
    PUT https://<host>:<port>/has/v1/conf/configkdcbackend?backendType=json&dir=/tmp/has/jsonbackend
    Code:200
    Content-Type:text/plain
    Content:
        Json backend set successfully.
```
### Configure HAS KDC
* Submit a HTTP PUT request.
```
    https://<host>:<port>/has/v1/conf/configkdc?realm=<realm>&host=<host>&port=<port>
```
Example:
```
    PUT https://<host>:<port>/has/v1/conf/configkdc?realm=HADOOP.COM&host=localhost&port=88
    Code:200
    Content-Type:text/plain
    Content:
        HAS server KDC set successfully.
 ```   
### Get HAS krb5 conf
* Submit a HTTP GET request.
```
    https://<host>:<port>/has/v1/getkrb5conf
```
Example:
```   
    GET https://<host>:<port>/has/v1/getkrb5conf
    Code:200
    Content-Disposition:attachment;filename=krb5.conf
```
### Get Has conf
* Submit a HTTP GET request.
```
    https://<host>:<port>/has/v1/gethasconf
```
Example:
```
    GET https://<host>:<port>/has/v1/gethasconf
    Code:200
    Content-Disposition:attachment;filename=has-client.conf
```
## Admin API        AuthType:HTTPS,kerberos  
### Get HAS principals
* Submit a HTTP GET request.
```
    https://<host>:<port>/has/v1/admin/getprincipals [?exp=<exp>]
```
Example:
```   
    GET https://<host>:<port>/has/v1/admin/getprincipals
    Code:200
    Content-Type:application/json
    Content:
        {
            "result":"success",
            "msg":"[
                        \"HTTP\\\/host1@HADOOP.COM\",
                        \"HTTP\\\/host2@HADOOP.COM\",
                        \"hbase\\\/host2@HADOOP.COM\",
                        \"hdfs\\\/host1@HADOOP.COM\",
                        \"hdfs\\\/host2@HADOOP.COM\",
                        \"yarn\\\/host1@HADOOP.COM\",
                        \"yarn\\\/host2@HADOOP.COM\"
                   ]"
        }
```     
### Add HAS principal
```
    https://<host>:<port>/has/v1/admin/addprincipal?principal=<principal> [&password=<password>]
```
Example:
```
    POST https://<host>:<port>/has/v1/admin/addprincipal?principal=admin
    Code:200
    Content-Type:application/json
    Content:
        {
            "result":"success",
            "msg":"Add principal successfully."
        }
```  
### Rename HAS principal
* Submit a HTTP POST request.
```
    https://<host>:<port>/has/v1/admin/renameprincipal?oldprincipal=<oldprincipal>&newprincipal=<newprincipal>
```
Example:
```
    POST https://<host>:<port>/has/v1/admin/renameprincipal?oldprincipal=admin&newprincipal=admin/admin
    Code:200
    Content-Type:application/json
    Content:
        {
            "result":"success",
            "msg":"Rename principal successfully."
        }
```   
### Delete HAS principal
* Submit a HTTP DELETE request.
```
    https://<host>:<port>/has/v1/admin/deleteprincipal?principal=<principal>
```
Example:
```
    DELETE https://<host>:<port>/has/v1/admin/deleteprincipal?principal=admin'
    Code:200
    Content-Type:application/json
    Content:
        {
            "result":"success",
            "msg":"Delete principal successfully."
        }
```     
### Create service principals
* Submit a HTTP PUT request.
```
    https://<host>:<port>/has/v1/admin/createprincipals
    Content-Type:application/json
```
Example:
```   
    Request:
    PUT https://<host>:<port>/has/v1/admin/createprincipals
    Content-Type:application/json
    Content:
    {
        HOSTS: [
            {"name":"host1","hostRoles":"HDFS"},    //hostRoles segmentation by ,
            {"name":"host2","hostRoles":"HDFS,HBASE"}
        ] 
    }
    Response:
    Code:200
    Content-Type:application/json
    Content:
        {
            "result":"success",
            "msg":"Already add princ :hdfs\/host1@HADOOP.COM
                   Already add princ :yarn\/host1@HADOOP.COM
                   Already add princ :hdfs\/host2@HADOOP.COM
                   Already add princ :yarn\/host2@HADOOP.COM
                   Already add princ :hbase\/host2@HADOOP.COM"
        }
```
### Export service keytabs
* Submit a HTTP GET request.
```
    https://<host>:<port>/has/v1/kadmin/exportkeytabs?host=<host> [&role=<role>]
```
Example:
```
    GET https://<host>:<port>/has/v1/admin/exportkeytabs?host=host1
    Code:200
    Content-Disposition:attachment;filename=keytab.zip
```
## User API        AuthType:HTTPS

### Start HAS server
* Submit a HTTP GET request.
```
    https://<host>:<port>/has/v1/kdcstart
```
Example:
```
    GET https://<host>:<port>/has/v1/kdcstart
    Code:200
    Content-Type:application/json
    Content:
        {
            "result":"success",
            "msg":"Succeed in starting KDC server."
        }
```
### Init HAS server
* Submit a HTTP GET request.
```
    https://<host>:<port>/has/v1/kdcinit
```
Example:
``` 
    GET https://<host>:<port>/has/v1/kdcinit
    Code:200
    Content-Disposition:attachment;filename=admin.keytab
```
### Get hostRoles list
* Submit a HTTP GET request.
```
    https://<host>:<port>/has/v1/hostroles
```
Example:
```
    GET https://<host>:<port>/has/v1/hostroles
    Code:200
    Content-Type:application/json
    
    Content:
    [
        {"HostRole":"HDFS","PrincipalNames":["HTTP","hdfs"]},
        {"HostRole":"YARN","PrincipalNames":["yarn"]},
        {"HostRole":"HBASE","PrincipalNames":["hbase"]},
        {"HostRole":"ZOOKEEPER","PrincipalNames":["zookeeper"]}
    ]
```
