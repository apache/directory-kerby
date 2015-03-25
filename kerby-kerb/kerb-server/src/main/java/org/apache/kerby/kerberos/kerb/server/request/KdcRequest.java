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
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.preauth.KdcFastContext;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthContext;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.KrbErrorException;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.*;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcOption;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcOptions;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.spec.ticket.EncTicketPart;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TicketFlag;
import org.apache.kerby.kerberos.kerb.spec.ticket.TicketFlags;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Date;
import java.util.List;

public abstract class KdcRequest {

    protected KdcContext kdcContext;

    private Ticket ticket;
    private boolean isPreAuthenticated;
    private KdcReq kdcReq;
    private KdcRep reply;
    private InetAddress clientAddress;
    private boolean isTcp;
    private EncryptionType encryptionType;
    private EncryptionKey clientKey;
    private KrbIdentity clientEntry;
    private KrbIdentity serverEntry;
    private EncryptionKey serverKey;
    private KrbIdentity tgsEntry;
    private PreauthContext preauthContext;
    private KdcFastContext fastContext;
    private PrincipalName serverPrincipal;

    public KdcRequest(KdcReq kdcReq, KdcContext kdcContext) {
        this.kdcReq = kdcReq;
        this.kdcContext = kdcContext;
        this.preauthContext = kdcContext.getPreauthHandler()
                .preparePreauthContext(this);
        this.fastContext = new KdcFastContext();
    }

    public KdcContext getKdcContext() {
        return kdcContext;
    }

    public PreauthContext getPreauthContext() {
        return preauthContext;
    }

    public void process() throws KrbException {
        checkVersion();
        checkClient();
        checkServer();
        preauth();
        authenticate();
        issueTicket();
        makeReply();
    }

    public KdcReq getKdcReq() {
        return kdcReq;
    }

    public KrbIdentity getTgsEntry() {
        return tgsEntry;
    }

    public void setTgsEntry(KrbIdentity tgsEntry) {
        this.tgsEntry = tgsEntry;
    }

    public boolean isTcp() {
        return isTcp;
    }

    public void isTcp(boolean isTcp) {
        this.isTcp = isTcp;
    }

    public KrbMessage getReply() {
        return reply;
    }

    public void setReply(KdcRep reply) {
        this.reply = reply;
    }

    public InetAddress getClientAddress() {
        return clientAddress;
    }

    public void setClientAddress(InetAddress clientAddress) {
        this.clientAddress = clientAddress;
    }

    public EncryptionType getEncryptionType() {
        return encryptionType;
    }

    public void setEncryptionType(EncryptionType encryptionType) {
        this.encryptionType = encryptionType;
    }

    public Ticket getTicket() {
        return ticket;
    }

    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

    public boolean isPreAuthenticated() {
        return isPreAuthenticated;
    }

    public void setPreAuthenticated(boolean isPreAuthenticated) {
        this.isPreAuthenticated = isPreAuthenticated;
    }

    public KrbIdentity getServerEntry() {
        return serverEntry;
    }

    public void setServerEntry(KrbIdentity serverEntry) {
        this.serverEntry = serverEntry;
    }

    public KrbIdentity getClientEntry() {
        return clientEntry;
    }

    public void setClientEntry(KrbIdentity clientEntry) {
        this.clientEntry = clientEntry;
    }

    public EncryptionKey getClientKey(EncryptionType encType) throws KrbException {
        return getClientEntry().getKey(encType);
    }

    public EncryptionKey getClientKey() {
        return clientKey;
    }

    public void setClientKey(EncryptionKey clientKey) {
        this.clientKey = clientKey;
    }

    public EncryptionKey getServerKey() {
        return serverKey;
    }

    public void setServerKey(EncryptionKey serverKey) {
        this.serverKey = serverKey;
    }

    public PrincipalName getTgsPrincipal() {
        PrincipalName result = new PrincipalName(kdcContext.getConfig().getTgsPrincipal());
        result.setRealm(kdcContext.getKdcRealm());
        return result;
    }

    protected abstract void makeReply() throws KrbException;

    protected void checkVersion() throws KrbException {
        KdcReq request = getKdcReq();

        int kerberosVersion = request.getPvno();
        if (kerberosVersion != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KDC_ERR_BAD_PVNO);
        }
    }

    protected void checkPolicy() throws KrbException {
        KrbIdentity entry = getClientEntry();

        if (entry.isDisabled()) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }

        if (entry.isLocked()) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }

        if (entry.getExpireTime().lessThan(new Date().getTime())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }
    }

    protected void checkClient() throws KrbException {
        KdcReq request = getKdcReq();

        PrincipalName clientPrincipal = request.getReqBody().getCname();
        String clientRealm = request.getReqBody().getRealm();
        if (clientRealm == null || clientRealm.isEmpty()) {
            clientRealm = kdcContext.getServerRealm();
        }
        clientPrincipal.setRealm(clientRealm);

        KrbIdentity clientEntry = getEntry(clientPrincipal.getName());
        setClientEntry(clientEntry);

        EncryptionType encType = request.getReqBody().getEtypes().listIterator().next();
        EncryptionKey clientKey = clientEntry.getKeys().get(encType);
        setClientKey(clientKey);
    }

    protected void preauth() throws KrbException {
        KdcReq request = getKdcReq();

        PaData preAuthData = request.getPaData();

        if (preauthContext.isPreauthRequired()) {
            if (preAuthData == null || preAuthData.isEmpty()) {
                KrbError krbError = makePreAuthenticationError(kdcContext);
                throw new KrbErrorException(krbError);
            } else {
                getPreauthHandler().verify(this, preAuthData);
            }
        }

        setPreAuthenticated(true);
    }

    protected void setPreauthRequired(boolean preauthRequired) {
        preauthContext.setPreauthRequired(preauthRequired);
    }

    protected boolean isPreauthRequired() {
        return preauthContext.isPreauthRequired();
    }

    protected PreauthHandler getPreauthHandler() {
        return kdcContext.getPreauthHandler();
    }

    protected void checkEncryptionType() throws KrbException {
        List<EncryptionType> requestedTypes = getKdcReq().getReqBody().getEtypes();

        EncryptionType bestType = EncryptionUtil.getBestEncryptionType(requestedTypes,
                kdcContext.getConfig().getEncryptionTypes());

        if (bestType == null) {
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP);
        }

        setEncryptionType(bestType);
    }

    protected void authenticate() throws KrbException {
        checkEncryptionType();
        checkPolicy();
    }

    protected void issueTicket() throws KrbException {
        KdcReq request = getKdcReq();

        EncryptionType encryptionType = getEncryptionType();
        EncryptionKey serverKey = getServerEntry().getKeys().get(encryptionType);

        PrincipalName ticketPrincipal = request.getReqBody().getSname();

        EncTicketPart encTicketPart = new EncTicketPart();
        KdcConfig config = kdcContext.getConfig();

        TicketFlags ticketFlags = new TicketFlags();
        encTicketPart.setFlags(ticketFlags);
        ticketFlags.setFlag(TicketFlag.INITIAL);

        if (isPreAuthenticated()) {
            ticketFlags.setFlag(TicketFlag.PRE_AUTH);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.FORWARDABLE)) {
            if (!config.isForwardableAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.FORWARDABLE);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.PROXIABLE)) {
            if (!config.isProxiableAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.PROXIABLE);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.ALLOW_POSTDATE)) {
            if (!config.isPostdatedAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.MAY_POSTDATE);
        }

        KdcOptions kdcOptions = request.getReqBody().getKdcOptions();

        EncryptionKey sessionKey = EncryptionHandler.random2Key(getEncryptionType());
        encTicketPart.setKey(sessionKey);

        encTicketPart.setCname(request.getReqBody().getCname());
        encTicketPart.setCrealm(request.getReqBody().getRealm());

        TransitedEncoding transEnc = new TransitedEncoding();
        encTicketPart.setTransited(transEnc);
        String serverRealm = request.getReqBody().getRealm();

        KerberosTime now = KerberosTime.now();
        encTicketPart.setAuthTime(now);

        KerberosTime krbStartTime = request.getReqBody().getFrom();
        if (krbStartTime == null || krbStartTime.lessThan(now) ||
                krbStartTime.isInClockSkew(config.getAllowableClockSkew())) {
            krbStartTime = now;
        }
        if (krbStartTime.greaterThan(now)
                && !krbStartTime.isInClockSkew(config.getAllowableClockSkew())
                && !kdcOptions.isFlagSet(KdcOption.POSTDATED)) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CANNOT_POSTDATE);
        }

        if (kdcOptions.isFlagSet(KdcOption.POSTDATED)) {
            if (!config.isPostdatedAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.POSTDATED);
            encTicketPart.setStartTime(krbStartTime);
        }

        KerberosTime krbEndTime = request.getReqBody().getTill();
        if (krbEndTime == null) {
            krbEndTime = krbStartTime.extend(config.getMaximumTicketLifetime() * 1000);
        } else if (krbStartTime.greaterThan(krbEndTime)) {
            throw new KrbException(KrbErrorCode.KDC_ERR_NEVER_VALID);
        }
        encTicketPart.setEndTime(krbEndTime);

        long ticketLifeTime = Math.abs(krbEndTime.diff(krbStartTime));
        if (ticketLifeTime < config.getMinimumTicketLifetime()) {
            throw new KrbException(KrbErrorCode.KDC_ERR_NEVER_VALID);
        }

        KerberosTime krbRtime = request.getReqBody().getRtime();
        if (kdcOptions.isFlagSet(KdcOption.RENEWABLE_OK)) {
            kdcOptions.setFlag(KdcOption.RENEWABLE);
        }
        if (kdcOptions.isFlagSet(KdcOption.RENEWABLE)) {
            if (!config.isRenewableAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.RENEWABLE);

            if (krbRtime == null) {
                krbRtime = KerberosTime.NEVER;
            }
            KerberosTime allowedMaximumRenewableTime = krbStartTime;
            allowedMaximumRenewableTime.extend(config.getMaximumRenewableLifetime() * 1000);
            if (krbRtime.greaterThan(allowedMaximumRenewableTime)) {
                krbRtime = allowedMaximumRenewableTime;
            }
            encTicketPart.setRenewtill(krbRtime);
        }

        HostAddresses hostAddresses = request.getReqBody().getAddresses();
        if (hostAddresses == null || hostAddresses.isEmpty()) {
            if (!config.isEmptyAddressesAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }
        } else {
            encTicketPart.setClientAddresses(hostAddresses);
        }

        EncryptedData encryptedData = EncryptionUtil.seal(encTicketPart,
                serverKey, KeyUsage.KDC_REP_TICKET);

        Ticket newTicket = new Ticket();
        newTicket.setSname(ticketPrincipal);
        newTicket.setEncryptedEncPart(encryptedData);
        newTicket.setRealm(serverRealm);
        newTicket.setEncPart(encTicketPart);

        setTicket(newTicket);
    }

    private void checkServer() throws KrbException {
        KdcReq request = getKdcReq();

        KrbIdentity tgsEntry = getEntry(getTgsPrincipal().getName());
        setTgsEntry(tgsEntry);

        PrincipalName principal = request.getReqBody().getSname();
        String serverRealm = request.getReqBody().getRealm();
        if (serverRealm == null || serverRealm.isEmpty()) {
            serverRealm = kdcContext.getServerRealm();
        }
        principal.setRealm(serverRealm);

        KrbIdentity serverEntry = getEntry(principal.getName());
        setServerEntry(serverEntry);

        EncryptionType encType = request.getReqBody().getEtypes().listIterator().next();
        EncryptionKey serverKey = serverEntry.getKeys().get(encType);
        setServerKey(serverKey);
    }

    protected KrbError makePreAuthenticationError(KdcContext kdcContext) throws KrbException {
        EncryptionType requestedType = getEncryptionType();
        List<EncryptionType> encryptionTypes = kdcContext.getConfig().getEncryptionTypes();
        boolean isNewEtype = true;

        EtypeInfo2 eTypeInfo2 = new EtypeInfo2();

        EtypeInfo eTypeInfo = new EtypeInfo();

        for (EncryptionType encryptionType : encryptionTypes) {
            if (!isNewEtype) {
                EtypeInfoEntry etypeInfoEntry = new EtypeInfoEntry();
                etypeInfoEntry.setEtype(encryptionType);
                etypeInfoEntry.setSalt(null);
                eTypeInfo.add(etypeInfoEntry);
            }

            EtypeInfo2Entry etypeInfo2Entry = new EtypeInfo2Entry();
            etypeInfo2Entry.setEtype(encryptionType);
            eTypeInfo2.add(etypeInfo2Entry);
        }

        byte[] encTypeInfo = null;
        byte[] encTypeInfo2 = null;
        if (!isNewEtype) {
            encTypeInfo = KrbCodec.encode(eTypeInfo);
        }
        encTypeInfo2 = KrbCodec.encode(eTypeInfo2);

        MethodData methodData = new MethodData();
        methodData.add(new PaDataEntry(PaDataType.ENC_TIMESTAMP, null));
        if (!isNewEtype) {
            methodData.add(new PaDataEntry(PaDataType.ETYPE_INFO, encTypeInfo));
        }
        methodData.add(new PaDataEntry(PaDataType.ETYPE_INFO2, encTypeInfo2));

        KrbError krbError = new KrbError();
        krbError.setErrorCode(KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED);
        byte[] encodedData = KrbCodec.encode(methodData);
        krbError.setEdata(encodedData);

        return krbError;
    }

    protected KrbIdentity getEntry(String principal) throws KrbException {
        KrbIdentity entry = null;
        KrbErrorCode krbErrorCode = KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN;

        try {
            entry = kdcContext.getIdentityService().getIdentity(principal);
        } catch (Exception e) {
            throw new KrbException(krbErrorCode, e);
        }

        if (entry == null) {
            throw new KrbException(krbErrorCode);
        }

        return entry;
    }

    public ByteBuffer getRequestBody() throws KrbException {
        return null;
    }

    public EncryptionKey getArmorKey() throws KrbException {
        return fastContext.getArmorKey();
    }

    public PrincipalName getServerPrincipal() {
        return serverPrincipal;
    }
}
