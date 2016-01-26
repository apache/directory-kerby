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

### Initiate a KrbClient
* Initiate a KrbClient with prepared KrbConfig.
<pre>
KrbClient krbClient = new KrbClient(krbConfig);
</pre>
* Initiate a KrbClient with with conf dir.
<pre>
KrbClient krbClient = new KrbClient(confDir);
</pre>

### Request a TGT
* Request a TGT with user plain password credential
<pre>
requestTgtWithPassword(principal, password);
</pre>
* Request a TGT with user token credential
<pre>
requestTgtWithToken(token, armorCache);
</pre>

### Request a service ticket
* Request a service ticket with user TGT credential for a server
<pre>
requestServiceTicketWithTgt(tgt, serverPrincipal);
</pre>
* Request a service ticket with user AccessToken credential for a server
<pre>
requestServiceTicketWithAccessToken(accessToken, serverPrincipal, armorCache);
</pre>
