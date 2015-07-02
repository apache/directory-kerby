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
