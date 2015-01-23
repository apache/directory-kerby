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
import org.apache.kerby.kerberos.kerb.codec.KrbCodec;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.ap.ApOption;
import org.apache.kerby.kerberos.kerb.spec.ap.ApReq;
import org.apache.kerby.kerberos.kerb.spec.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.spec.common.*;
import org.apache.kerby.kerberos.kerb.spec.kdc.*;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.ticket.EncTicketPart;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TicketFlag;

import java.nio.ByteBuffer;

public class TgsRequest extends KdcRequest {

    private EncryptionKey tgtSessionKey;

    public TgsRequest(TgsReq tgsReq, KdcContext kdcContext) {
        super(tgsReq, kdcContext);

        setPreauthRequired(true);
    }

    public EncryptionKey getTgtSessionKey() {
        return tgtSessionKey;
    }

    public void setTgtSessionKey(EncryptionKey tgtSessionKey) {
        this.tgtSessionKey = tgtSessionKey;
    }

    public void verifyAuthenticator(PaDataEntry paDataEntry) throws KrbException {
        ApReq apReq = KrbCodec.decode(paDataEntry.getPaDataValue(), ApReq.class);

        if (apReq.getPvno() != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
        }

        if (apReq.getMsgType() != KrbMessageType.AP_REQ) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_MSG_TYPE);
        }

        EncryptionType encType = getKdcReq().getReqBody().getEtypes().listIterator().next();
        EncryptionKey tgsKey = getTgsEntry().getKeys().get(encType);

        Ticket ticket = apReq.getTicket();
        if (ticket.getTktvno() != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
        }

        EncTicketPart encPart = EncryptionUtil.unseal(ticket.getEncryptedEncPart(),
                tgsKey, KeyUsage.KDC_REP_TICKET, EncTicketPart.class);
        ticket.setEncPart(encPart);

        EncryptionKey encKey = null;
        //if (apReq.getApOptions().isFlagSet(ApOptions.USE_SESSION_KEY)) {
        encKey = ticket.getEncPart().getKey();

        if (encKey == null) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_NOKEY);
        }
        Authenticator authenticator = EncryptionUtil.unseal(apReq.getEncryptedAuthenticator(),
                encKey, KeyUsage.TGS_REQ_AUTH, Authenticator.class);

        if (!authenticator.getCname().equals(ticket.getEncPart().getCname())) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADMATCH);
        }

        HostAddresses hostAddresses = ticket.getEncPart().getClientAddresses();
        if (hostAddresses == null || hostAddresses.isEmpty()) {
            if (!kdcContext.getConfig().isEmptyAddressesAllowed()) {
                throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
            }
        } else if (!hostAddresses.contains(getClientAddress())) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
        }

        PrincipalName serverPrincipal = ticket.getSname();
        serverPrincipal.setRealm(ticket.getRealm());
        PrincipalName clientPrincipal = authenticator.getCname();
        clientPrincipal.setRealm(authenticator.getCrealm());

        if (!authenticator.getCtime().isInClockSkew(
                kdcContext.getConfig().getAllowableClockSkew() * 1000)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_SKEW);
        }

        KerberosTime now = KerberosTime.now();
        KerberosTime startTime = ticket.getEncPart().getStartTime();
        if (startTime == null) {
            startTime = ticket.getEncPart().getAuthTime();
        }
        if (! startTime.lessThan(now)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_NYV);
        }

        KerberosTime endTime = ticket.getEncPart().getEndTime();
        if (! endTime.greaterThan(now)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_EXPIRED);
        }

        apReq.getApOptions().setFlag(ApOption.MUTUAL_REQUIRED);

        setTgtSessionKey(ticket.getEncPart().getKey());
    }

    @Override
    protected void makeReply() throws KrbException {
        Ticket ticket = getTicket();

        TgsRep reply = new TgsRep();

        reply.setCname(getClientEntry().getPrincipal());
        reply.setCrealm(kdcContext.getServerRealm());
        reply.setTicket(ticket);

        EncKdcRepPart encKdcRepPart = makeEncKdcRepPart();
        reply.setEncPart(encKdcRepPart);

        EncryptionKey sessionKey = getTgtSessionKey();
        EncryptedData encryptedData = EncryptionUtil.seal(encKdcRepPart,
                sessionKey, KeyUsage.TGS_REP_ENCPART_SESSKEY);
        reply.setEncryptedEncPart(encryptedData);

        setReply(reply);
    }

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

    public ByteBuffer getRequestBody() throws KrbException {
        return null;
    }

    public EncryptionKey getArmorKey() throws KrbException {
        return null;
    }
}
