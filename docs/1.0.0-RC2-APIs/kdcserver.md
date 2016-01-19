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
