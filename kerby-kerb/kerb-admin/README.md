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

kerb-admin
============

### Initiate a Kadmin
* Initiate a Kadmin with confDir.
<pre>
Kadmin kadmin = new Kadmin(confDir);
</pre>
* Initiate a Kadmin with kdcSetting and backend.
<pre>
Kadmin kadmin = new Kadmin(kdcSetting, backend);
</pre>

### Principal operating
* Add principle with principal name.
<pre>
addPrincipal(principal);
</pre>
* Add principle with principal name and password.
<pre>
addPrincipal(principal, password);
</pre>
* Add principle with principal name and kOptions.
<pre>
addPrincipal(principal, kOptions);
</pre>
* Add principle with principal name, password and kOptions.
<pre>
addPrincipal(principal, password kOptions);
</pre>
* Delete principle with principal name.
<pre>
deletePrincipal(principal);
</pre>
* Modify principle with principal name and kOptions.
<pre>
modifyPrincipal(principal, kOptions);
</pre>
* Rename principle.
<pre>
renamePrincipal(oldPrincipalName, newPrincipalName);
</pre>
* Get principle with principal name.
<pre>
getPrincipal(principalName);
</pre>
* Get all the principles.
<pre>
getPrincipals();
</pre>
* Update password with principal name and new password.
<pre>
updatePassword(principal, newPassword);
</pre>
* Export all identity keys to the specified keytab file.
<pre>
exportKeyTab(keyTabFile);
</pre>





