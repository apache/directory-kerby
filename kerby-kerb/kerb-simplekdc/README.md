kerb-simplekdc
============

### Kdc server
</pre>
* Start simple kdc server.
<pre>
start();
</pre>
* Set KDC realm for ticket request
<pre>
setKdcRealm(realm);
</pre>
* Set KDC host.
<pre>
setKdcHost(kdcHost);
</pre>
* Set KDC tcp port.
<pre>
setKdcTcpPort(kdcTcpPort);
</pre>
* Set KDC udp port. Only makes sense when allowUdp is set.
<pre>
setKdcUdpPort(kdcUdpPort);
</pre>
* Set to allow TCP or not.
<pre>
setAllowTcp(allowTcp);
</pre>
* Set to allow UDP or not.
<pre>
setAllowUdp(allowUdp);

### Kadmin
</pre>
* Create principle with principal name.
<pre>
createPrincipal(principal);
</pre>
* Add principle with principal name and password.
<pre>
createPrincipal(principal, password);
</pre>
* Create principles with principal names.
<pre>
createPrincipals(principals);
</pre>
* Creates principals and export their keys to the specified keytab file.
<pre>
createAndExportPrincipals(keytabFile principals);
</pre>
* Delete principle with principal name.
<pre>
deletePrincipal(principal);
</pre>
</pre>
* Delete principles with principal names.
<pre>
deletePrincipals(principals);
</pre>
</pre>
* Export principles to keytab file.
<pre>
exportPrincipals(keytabFile);
</pre>

