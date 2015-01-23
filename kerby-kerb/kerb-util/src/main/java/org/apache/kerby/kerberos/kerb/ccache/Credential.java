/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kerb.ccache;

import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.common.AuthorizationData;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.HostAddresses;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.spec.ticket.AbstractServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TicketFlags;

import java.io.IOException;

public class Credential
{
    private static String CONF_REALM = "X-CACHECONF:";

    private PrincipalName clientName;
    private String clientRealm;
    private PrincipalName serverName;
    private String serverRealm;
    private EncryptionKey key;
    private KerberosTime authTime;
    private KerberosTime startTime;
    private KerberosTime endTime;
    private KerberosTime renewTill;
    private HostAddresses clientAddresses;
    private AuthorizationData authzData;
    private boolean isEncInSKey;
    private TicketFlags ticketFlags;
    private Ticket ticket;
    private Ticket secondTicket;

    public Credential() {

    }

    public Credential(TgtTicket tgt) {
        PrincipalName clientPrincipal = tgt.getClientPrincipal();

        clientPrincipal.setRealm(tgt.getRealm());

        init(tgt, clientPrincipal);
    }

    public Credential(AbstractServiceTicket tkt, PrincipalName clientPrincipal) {
        init(tkt, clientPrincipal);
    }

    private void init(AbstractServiceTicket tkt, PrincipalName clientPrincipal) {
        EncKdcRepPart kdcRepPart = tkt.getEncKdcRepPart();

        this.serverName = kdcRepPart.getSname();
        this.serverRealm = kdcRepPart.getSrealm();
        this.serverName.setRealm(serverRealm);

        this.clientName = clientPrincipal;

        this.key = kdcRepPart.getKey();
        this.authTime = kdcRepPart.getAuthTime();
        this.startTime = kdcRepPart.getStartTime();
        this.endTime = kdcRepPart.getEndTime();

        this.renewTill = kdcRepPart.getRenewTill();

        this.ticketFlags = kdcRepPart.getFlags();
        this.clientAddresses = kdcRepPart.getCaddr();

        this.ticket = tkt.getTicket();

        this.isEncInSKey = false;

        this.secondTicket = null;
    }

    public PrincipalName getServicePrincipal() {
        return serverName;
    }

    public KerberosTime getAuthTime() {
        return authTime;
    }

    public KerberosTime getEndTime() {
        return endTime;
    }

    public int getEType() {
        return key.getKeyType().getValue();
    }

    public PrincipalName getClientName() {
        return clientName;
    }

    public PrincipalName getServerName() {
        return serverName;
    }

    public String getClientRealm() {
        return clientRealm;
    }

    public EncryptionKey getKey() {
        return key;
    }

    public KerberosTime getStartTime() {
        return startTime;
    }

    public KerberosTime getRenewTill() {
        return renewTill;
    }

    public HostAddresses getClientAddresses() {
        return clientAddresses;
    }

    public AuthorizationData getAuthzData() {
        return authzData;
    }

    public boolean isEncInSKey() {
        return isEncInSKey;
    }

    public TicketFlags getTicketFlags() {
        return ticketFlags;
    }

    public Ticket getTicket() {
        return ticket;
    }

    public Ticket getSecondTicket() {
        return secondTicket;
    }

    public void load(CredCacheInputStream ccis, int version) throws IOException {
        this.clientName = ccis.readPrincipal(version);
        if (clientName == null) {
            throw new IOException("Invalid client principal name");
        }

        this.serverName = ccis.readPrincipal(version);
        if (serverName == null) {
            throw new IOException("Invalid server principal name");
        }

        boolean isConfEntry = false;

        if (serverName.getRealm().equals(CONF_REALM)) {
            isConfEntry = true;
        }

        this.key = ccis.readKey(version);

        KerberosTime[] times = ccis.readTimes();
        this.authTime = times[0];
        this.startTime = times[1];
        this.endTime = times[2];
        this.renewTill = times[3];

        this.isEncInSKey = ccis.readIsSkey();

        this.ticketFlags = ccis.readTicketFlags();

        this.clientAddresses = ccis.readAddr();

        this.authzData = ccis.readAuthzData();

        if (isConfEntry) {
            byte[] confData = ccis.readCountedOctets();
            // ignoring confData for now
        } else {
            this.ticket = ccis.readTicket();
        }

        this.secondTicket = ccis.readTicket();

        // might skip krb5_ccache_conf_data/fast_avail/krbtgt/REALM@REALM in MIT KRB5
    }

    public void store(CredCacheOutputStream ccos, int version) throws IOException {
        ccos.writePrincipal(clientName, version);
        ccos.writePrincipal(serverName, version);
        ccos.writeKey(key, version);

        ccos.writeTimes(new KerberosTime[]{authTime, startTime, endTime, renewTill});

        ccos.writeIsSkey(isEncInSKey);
 
        ccos.writeTicketFlags(ticketFlags);

        ccos.writeAddresses(clientAddresses);

        ccos.writeAuthzData(authzData);

        ccos.writeTicket(ticket);

        ccos.writeTicket(secondTicket);
    }
}
