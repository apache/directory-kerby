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

kerb-client
============

## 1. KrbClient
### Initiate a KrbClient
* Initiate a KrbClient with prepared KrbConfig.
<pre>
KrbClient krbClient = new KrbClient(adminConfig);
</pre>
* Initiate a KrbClient with conf dir.
<pre>
KrbClient krbClient = new KrbClient(confDir);
</pre>

### Request a TGT
* Request a TGT with using well prepared requestOptions.
<pre>
requestTgt(requestOptions);
</pre>
* Request a TGT with user plain password credential
<pre>
requestTgt(principal, password);
</pre>
* Request a TGT with user plain keytab credential
<pre>
requestTgt(principal, keytabFile);
</pre>

### Request a service ticket
* Request a service ticket with a TGT targeting for a server
<pre>
requestSgt(tgt, serverPrincipal);
</pre>
* Request a service ticket provided request options
<pre>
requestSgt(requestOptions);
</pre>

## 2. KrbTokenClient
### Initiate a KrbTokenClient
* Initiate a KrbTokenClient with prepared KrbConfig.
<pre>
KrbTokenClient krbTokenClient = new KrbTokenClient(adminConfig);
</pre>
* Initiate a KrbTokenClient with conf dir.
<pre>
KrbTokenClient krbTokenClient = new KrbTokenClient(confDir);
</pre>
* Initiate a KrbTokenClient with prepared KrbClient.
<pre>
KrbTokenClient krbTokenClient = new KrbTokenClient(krbClient);
</pre>

### Request a TGT
* Request a TGT with user token credential
<pre>
requestTgtWithToken(token, armorCache);
</pre>

### Request a service ticket
</pre>
* Request a service ticket with user AccessToken credential for a server
<pre>
requestSgt(accessToken, serverPrincipal, armorCache);
</pre>

## 3. KrbPkinitClient
### Initiate a KrbPkinitClient
* Initiate a KrbPkinitClient with prepared KrbConfig.
<pre>
KrbPkinitClient krbPkinitClient = new KrbPkinitClient(adminConfig);
</pre>
* Initiate a KrbPkinitClient with conf dir.
<pre>
KrbPkinitClient krbPkinitClient = new KrbPkinitClient(confDir);
</pre>
* Initiate a KrbPkinitClient with prepared KrbClient.
<pre>
KrbPkinitClient krbPkinitClient = new KrbPkinitClient(krbClient);
</pre>

### Request a TGT
* Request a TGT with using Anonymous PKINIT
<pre>
requestTgt();
</pre>

