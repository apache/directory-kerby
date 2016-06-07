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

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.ap.ApOption;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.HostAddresses;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.base.LastReq;
import org.apache.kerby.kerberos.kerb.type.base.LastReqEntry;
import org.apache.kerby.kerberos.kerb.type.base.LastReqType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.EncTgsRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.type.kdc.TgsRep;
import org.apache.kerby.kerberos.kerb.type.kdc.TgsReq;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

public class TgsRequest extends KdcRequest {
    private static final Logger LOG = LoggerFactory.getLogger(TgsRequest.class);

    private EncryptionKey tgtSessionKey;
    private Ticket tgtTicket;

    /**
     * @param tgsReq TGS request
     * @param kdcContext kdc context
     */
    public TgsRequest(TgsReq tgsReq, KdcContext kdcContext) {
        super(tgsReq, kdcContext);

        setPreauthRequired(true);
    }

    /**
     * Get tgt session key.
     *
     * @return The tgt session key
     */
    public EncryptionKey getTgtSessionKey() {
        return tgtSessionKey;
    }

    /**
     * Set tgt session key.
     *
     * @param tgtSessionKey The tgt session key
     */
    public void setTgtSessionKey(EncryptionKey tgtSessionKey) {
        this.tgtSessionKey = tgtSessionKey;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void checkClient() throws KrbException {
        // Nothing to do at this phase because client couldn't be checked out yet.
    }

    /**
     * Get tgt ticket.
     *
     * @return The tgt ticket.
     */
    public Ticket getTgtTicket() {
        return tgtTicket;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void issueTicket() throws KrbException {
        TicketIssuer issuer = new ServiceTicketIssuer(this);
        Ticket newTicket = issuer.issueTicket();
        LOG.info("TGS_REQ ISSUE: authtime " + newTicket.getEncPart().getAuthTime().getTime() + ","
                + newTicket.getEncPart().getCname() + " for "
                + newTicket.getSname());
        setTicket(newTicket);
    }

    /**
     * Verify authenticator.
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param paDataEntry preauthentication data entry
     */
    public void verifyAuthenticator(PaDataEntry paDataEntry) throws KrbException {
        ApReq apReq = KrbCodec.decode(paDataEntry.getPaDataValue(), ApReq.class);

        if (apReq.getPvno() != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
        }

        if (apReq.getMsgType() != KrbMessageType.AP_REQ) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_MSG_TYPE);
        }

        tgtTicket = apReq.getTicket();
        EncryptionType encType = tgtTicket.getEncryptedEncPart().getEType();
        EncryptionKey tgsKey = getTgsEntry().getKeys().get(encType);
        if (tgtTicket.getTktvno() != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
        }

        EncTicketPart encPart = EncryptionUtil.unseal(tgtTicket.getEncryptedEncPart(),
            tgsKey, KeyUsage.KDC_REP_TICKET, EncTicketPart.class);
        tgtTicket.setEncPart(encPart);

        EncryptionKey encKey = null;
        //if (apReq.getApOptions().isFlagSet(ApOptions.USE_SESSION_KEY)) {
        encKey = tgtTicket.getEncPart().getKey();

        if (encKey == null) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_NOKEY);
        }

        Authenticator authenticator = EncryptionUtil.unseal(apReq.getEncryptedAuthenticator(),
            encKey, KeyUsage.TGS_REQ_AUTH, Authenticator.class);

        if (!authenticator.getCname().equals(tgtTicket.getEncPart().getCname())) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADMATCH);
        }

        HostAddresses hostAddresses = tgtTicket.getEncPart().getClientAddresses();
        if (hostAddresses == null || hostAddresses.isEmpty()) {
            if (!getKdcContext().getConfig().isEmptyAddressesAllowed()) {
                throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
            }
        } else if (!hostAddresses.contains(getClientAddress())) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
        }

        PrincipalName serverPrincipal = tgtTicket.getSname();
        serverPrincipal.setRealm(tgtTicket.getRealm());
        PrincipalName clientPrincipal = authenticator.getCname();
        clientPrincipal.setRealm(authenticator.getCrealm());
        KrbIdentity clientEntry = getEntry(clientPrincipal.getName());
        setClientEntry(clientEntry);

        if (!authenticator.getCtime().isInClockSkew(
            getKdcContext().getConfig().getAllowableClockSkew() * 1000)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_SKEW);
        }

        KerberosTime now = KerberosTime.now();
        KerberosTime startTime = tgtTicket.getEncPart().getStartTime();
        if (startTime == null) {
            startTime = tgtTicket.getEncPart().getAuthTime();
        }
        if (!startTime.lessThan(now)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_NYV);
        }

        KerberosTime endTime = tgtTicket.getEncPart().getEndTime();
        if (!endTime.greaterThan(now)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_EXPIRED);
        }

        apReq.getApOptions().setFlag(ApOption.MUTUAL_REQUIRED);

        setTgtSessionKey(tgtTicket.getEncPart().getKey());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void makeReply() throws KrbException {
        Ticket ticket = getTicket();

        TgsRep reply = new TgsRep();

        if (getClientEntry() == null) {
            reply.setCname(ticket.getEncPart().getCname());
        } else {
            reply.setCname(getClientEntry().getPrincipal());
        }
        reply.setCrealm(getKdcContext().getKdcRealm());
        reply.setTicket(ticket);

        EncKdcRepPart encKdcRepPart = makeEncKdcRepPart();
        reply.setEncPart(encKdcRepPart);

        EncryptionKey sessionKey;
        if (getToken() != null) {
            sessionKey = getSessionKey();
        } else {
            sessionKey = getTgtSessionKey();
        }
        EncryptedData encryptedData = EncryptionUtil.seal(encKdcRepPart,
            sessionKey, KeyUsage.TGS_REP_ENCPART_SESSKEY);
        reply.setEncryptedEncPart(encryptedData);

        setReply(reply);
    }

    /**
     * Make EncKdcRepPart.
     * @return encryption kdc response part
     */
    private EncKdcRepPart makeEncKdcRepPart() {
        KdcReq request = getKdcReq();
        Ticket ticket = getTicket();

        EncKdcRepPart encKdcRepPart = new EncTgsRepPart();

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

    /**
     * @return request body
     * @throws KrbException e
     */
    public ByteBuffer getRequestBody() throws KrbException {
        return null;
    }
}
