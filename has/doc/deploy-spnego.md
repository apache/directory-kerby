Deploy SPNEGO
================

## 1. Server Side Configuration(in server side has-server.conf)

To use Kerberos SPNEGO as the authentication mechanism, the authentication filter must be configured with the following init parameters:
- filter_auth_type : the keyword kerberos. For example: filter_auth_type = kerberos

## 2. Client Side Configuration(in client side hadmin.conf)

- filter_auth_type the keyword kerberos.  For example: filter_auth_type = kerberos
- admin_keytab: The path to the keytab file containning the credential for the admin principal. For example: admin_keytab = /etc/has/admin.keytab Here the admin.keytab the same as the server side.
- admin_keytab_principal: The admin principal. For example: admin_keytab_principal = kadmin/<YOUR-REALM.COM>@<YOUR-REALM.COM>
