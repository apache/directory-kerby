kerb-server
============

### Initiate kdc server
* Initiate a kdc server with prepared confDir.
<pre>
KdcServer server = new KdcServer(confDir);
</pre>

### Start and set kdc server
* Start kdc server.
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
</pre>
* Allow to debug so have more logs.
<pre>
enableDebug();
</pre>
* Allow to hook customized kdc implementation.
<pre>
setInnerKdcImpl(innerKdcImpl);
</pre>

### Stop kdc server
* Start kdc server.
<pre>
stop();
</pre>
