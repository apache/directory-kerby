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
package org.apache.kerby.kerberos.kerb.server.request;

import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.LastReq;
import org.apache.kerby.kerberos.kerb.type.base.LastReqEntry;
import org.apache.kerby.kerberos.kerb.type.base.LastReqType;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.EncAsRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AsRequest extends KdcRequest {
    private static final Logger LOG = LoggerFactory.getLogger(AsRequest.class);

    public AsRequest(AsReq asReq, KdcContext kdcContext) {
        super(asReq, kdcContext);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void checkClient() throws KrbException {
        KdcReq request = getKdcReq();
        PrincipalName clientPrincipal;
        if (isToken()) {
            LOG.info("The request is with token.");
            clientPrincipal = new PrincipalName(getToken().getSubject());
        } else {
            clientPrincipal = request.getReqBody().getCname();
        }
        if (clientPrincipal == null) {
            LOG.warn("Client principal name is null.");
            throw new KrbException(KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
        }
        String clientRealm = request.getReqBody().getRealm();
        if (clientRealm == null || clientRealm.isEmpty()) {
            clientRealm = getKdcContext().getKdcRealm();
        }
        clientPrincipal.setRealm(clientRealm);
        setClientPrincipal(clientPrincipal);

        KrbIdentity clientEntry;
        if (isToken()) {
            clientEntry = new KrbIdentity(clientPrincipal.getName());
            clientEntry.setExpireTime(new KerberosTime(getToken().getExpiredTime().getTime()));
        } else {
            clientEntry = getEntry(clientPrincipal.getName());
        }
        if (isAnonymous()) {
            clientEntry.setPrincipal(new PrincipalName(clientPrincipal.getName(), NameType.NT_WELLKNOWN));
        }

        if (clientEntry == null) {
            LOG.warn("Can't get the client entry.");
            throw new KrbException(KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
        }

        setClientEntry(clientEntry);

        for (EncryptionType encType : request.getReqBody().getEtypes()) {
            if (clientEntry.getKeys().containsKey(encType)) {
                EncryptionKey clientKey = clientEntry.getKeys().get(encType);
                setClientKey(clientKey);
                break;
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void issueTicket() throws KrbException {
        TicketIssuer issuer = new TgtTicketIssuer(this);
        Ticket newTicket = issuer.issueTicket();
        LOG.info("AS_REQ ISSUE: authtime " + newTicket.getEncPart().getAuthTime().getTime() + ","
                + newTicket.getEncPart().getCname() + " for "
                + newTicket.getSname());
        setTicket(newTicket);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void makeReply() throws KrbException {

        Ticket ticket = getTicket();

        AsRep reply = new AsRep();
        reply.setTicket(ticket);

        reply.setCname(getClientEntry().getPrincipal());
        reply.setCrealm(getKdcContext().getKdcRealm());

        EncKdcRepPart encKdcRepPart = makeEncKdcRepPart();
        reply.setEncPart(encKdcRepPart);

        EncryptionKey clientKey = getClientKey();
        EncryptedData encryptedData = EncryptionUtil.seal(encKdcRepPart,
            clientKey, KeyUsage.AS_REP_ENCPART);
        reply.setEncryptedEncPart(encryptedData);

        if (isPkinit()) {
            reply.setPaData(getPreauthContext().getOutputPaData());
        }

        setReply(reply);
    }

    /**
     * Make EncKdcRepPart.
     * @return encryption kdc request part
     */
    protected EncKdcRepPart makeEncKdcRepPart() {
        KdcReq request = getKdcReq();
        Ticket ticket = getTicket();

        EncKdcRepPart encKdcRepPart = new EncAsRepPart();

        //session key
        encKdcRepPart.setKey(ticket.getEncPart().getKey());

        LastReq lastReq = new LastReq();
        LastReqEntry entry = new LastReqEntry();
        entry.setLrType(LastReqType.THE_LAST_INITIAL);
        entry.setLrValue(new KerberosTime());
        lastReq.add(entry);
        encKdcRepPart.setLastReq(lastReq);

        encKdcRepPart.setNonce(request.getReqBody().getNonce());

        encKdcRepPart.setFlags(ticket.getEncPart().getFlags());
        encKdcRepPart.setAuthTime(ticket.getEncPart().getAuthTime());
        encKdcRepPart.setStartTime(ticket.getEncPart().getStartTime());
        encKdcRepPart.setEndTime(ticket.getEncPart().getEndTime());

        if (ticket.getEncPart().getFlags().isFlagSet(TicketFlag.RENEWABLE)) {
            encKdcRepPart.setRenewTill(ticket.getEncPart().getRenewtill());
        }

        encKdcRepPart.setSname(ticket.getSname());
        encKdcRepPart.setSrealm(ticket.getRealm());
        encKdcRepPart.setCaddr(ticket.getEncPart().getClientAddresses());

        return encKdcRepPart;
    }
}
