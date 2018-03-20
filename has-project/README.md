# Hadoop Authentication Service (HAS)
A dedicated Hadoop Authentication Server to support various authentication mechanisms other than just Kerberos.

# High level considerations
* Hadoop services are still strongly authenticated by Kerberos, as Kerberos is the only means so far to enable Hadoop security.
* Hadoop users can remain to use their familiar login methods.
* Security admins won't have to migrate and sync up their user accounts to Kerberos back and forth.
* New authentication mechanism can be customized and plugined.

# Architecture
![](https://github.com/apache/directory-kerby/blob/trunk/has-project/docs/has-overall.png)

# Design
Assuming existing users are stored in a SQL database (like MySQL), the detailed design and workflow may go like the following:
![](https://github.com/apache/directory-kerby/blob/trunk/has-project/docs/has-design.png)

# New mechanism plugin API

## HAS client plugin HasClientPlugin:

```Java
// Get the login module type ID, used to distinguish this module from others. 
// Should correspond to the server side module.
String getLoginType()

// Perform all the client side login logics, the results wrapped in an AuthToken, 
// will be validated by HAS server.
AuthToken login(Conf loginConf) throws HasLoginException
```

## HAS server plugin HasServerPlugin:

```Java
// Get the login module type ID, used to distinguish this module from others. 
// Should correspond to the client side module.
String getLoginType()

// Perform all the server side authentication logics, the results wrapped in an AuthToken, 
// will be used to exchange a Kerberos ticket.
AuthToken authenticate(AuthToken userToken) throws HasAuthenException
```

## Getting Started
Please look at [Getting Started](https://github.com/apache/directory-kerby/blob/trunk/has-project/docs/has-start.md) for details.
