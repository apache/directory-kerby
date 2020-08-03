<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

Deploy SPNEGO
================

## 1. Server Side Configuration(in server side has-server.conf)

To use Kerberos SPNEGO as the authentication mechanism, the authentication filter must be configured with the following init parameters:
- filter_auth_type : the keyword kerberos. For example: filter_auth_type = kerberos

## 2. Client Side Configuration(in client side admin.conf)

- filter_auth_type the keyword kerberos.  For example: filter_auth_type = kerberos
- admin_keytab: The path to the keytab file containing the credential for the admin principal(kadmin/<YOUR-REALM.COM>@<YOUR-REALM.COM>). For example: admin_keytab = /etc/has/admin.keytab
- realm: The realm of KDC. For example: realm = YOUR-REALM.COM
