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





