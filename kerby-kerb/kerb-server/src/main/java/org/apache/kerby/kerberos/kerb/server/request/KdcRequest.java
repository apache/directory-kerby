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
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.crypto.CheckSumHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.crypto.fast.FastUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.KdcRecoverableException;
import org.apache.kerby.kerberos.kerb.server.preauth.KdcFastContext;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthContext;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.EtypeInfo;
import org.apache.kerby.kerberos.kerb.type.base.EtypeInfo2;
import org.apache.kerby.kerberos.kerb.type.base.EtypeInfo2Entry;
import org.apache.kerby.kerberos.kerb.type.base.EtypeInfoEntry;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.MethodData;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.fast.ArmorType;
import org.apache.kerby.kerberos.kerb.type.fast.KrbFastArmor;
import org.apache.kerby.kerberos.kerb.type.fast.KrbFastArmoredReq;
import org.apache.kerby.kerberos.kerb.type.fast.KrbFastReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOption;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOptions;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Date;
import java.util.List;

public abstract class KdcRequest {

    private static final Logger LOG = LoggerFactory.getLogger(KdcRequest.class);
    private final KdcReq kdcReq;
    private final KdcContext kdcContext;

    private Ticket ticket;
    private boolean isPreAuthenticated;
    private KdcRep reply;
    private InetAddress clientAddress;
    private boolean isTcp = true;
    private EncryptionType encryptionType;
    private EncryptionKey clientKey;
    private KrbIdentity clientEntry;
    private KrbIdentity serverEntry;
    private EncryptionKey serverKey;
    private KrbIdentity tgsEntry;
    private PreauthContext preauthContext;
    private KdcFastContext fastContext;
    private PrincipalName clientPrincipal;
    private PrincipalName serverPrincipal;
    private byte[] innerBodyout;
    private AuthToken token;
    private boolean isToken = false;
    private boolean isPkinit = false;
    private boolean isAnonymous = false;
    private EncryptionKey sessionKey;
    private ByteBuffer reqPackage;

    /**
     * Get session key.
     *
     * @return session key
     */
    public EncryptionKey getSessionKey() {
        return sessionKey;
    }

    /**
     * Set session key.
     * @param sessionKey The session key
     */
    public void setSessionKey(EncryptionKey sessionKey) {
        this.sessionKey = sessionKey;
    }

    /**
     * kdc request constructor
     * @param kdcReq kdc request
     * @param kdcContext kdc context
     */
    public KdcRequest(KdcReq kdcReq, KdcContext kdcContext) {
        this.kdcReq = kdcReq;
        this.kdcContext = kdcContext;

        this.preauthContext = kdcContext.getPreauthHandler()
                .preparePreauthContext(this);
        this.fastContext = new KdcFastContext();
    }

    /**
     * Get kdc context.
     *
     * @return kdc context
     */
    public KdcContext getKdcContext() {
        return kdcContext;
    }

    /**
     * Get KdcReq.
     *
     * @return kdc request
     */
    public KdcReq getKdcReq() {
        return kdcReq;
    }

    /**
     * Get preauth context.
     *
     * @return preauthentication context.
     */
    public PreauthContext getPreauthContext() {
        return preauthContext;
    }

    /**
     * Process the kdcrequest from client and issue the ticket.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     */
    public void process() throws KrbException {
        checkVersion();
        checkTgsEntry();
        kdcFindFast();
        checkEncryptionType();

        if (PreauthHandler.isToken(getKdcReq().getPaData())) {
            isToken = true;
            preauth();
            checkClient();
            checkServer();
        } else {
            if (PreauthHandler.isPkinit(getKdcReq().getPaData())) {
                isPkinit = true;
            }
            checkClient();
            checkServer();
            preauth();
        }
        checkPolicy();
        issueTicket();
        makeReply();
    }

    /**
     * Check the tgs entry.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     */
    private void checkTgsEntry() throws KrbException {
        KrbIdentity tgsEntry = getEntry(getTgsPrincipal().getName());
        setTgsEntry(tgsEntry);
    }

    /**
     * Find the fast from padata.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    private void kdcFindFast() throws KrbException {

        PaData paData = getKdcReq().getPaData();
        if (paData != null) {
            for (PaDataEntry paEntry : paData.getElements()) {
                if (paEntry.getPaDataType() == PaDataType.FX_FAST) {
                    LOG.info("Found fast padata and start to process it.");
                    KrbFastArmoredReq fastArmoredReq = KrbCodec.decode(paEntry.getPaDataValue(),
                            KrbFastArmoredReq.class);
                    KrbFastArmor fastArmor = fastArmoredReq.getArmor();
                    armorApRequest(fastArmor);

                    EncryptedData encryptedData = fastArmoredReq.getEncryptedFastReq();
                    KrbFastReq fastReq = KrbCodec.decode(
                            EncryptionHandler.decrypt(encryptedData, getArmorKey(), KeyUsage.FAST_ENC),
                            KrbFastReq.class);
                    innerBodyout = KrbCodec.encode(fastReq.getKdcReqBody());

                    // TODO: get checksumed data in stream
                    CheckSum checkSum = fastArmoredReq.getReqChecksum();
                    if (checkSum == null) {
                        LOG.warn("Checksum is empty.");
                        throw new KrbException(KrbErrorCode.KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED);
                    }
                    byte[] reqBody = KrbCodec.encode(getKdcReq().getReqBody());
                        CheckSumHandler.verifyWithKey(checkSum, reqBody,
                            getArmorKey().getKeyData(), KeyUsage.FAST_REQ_CHKSUM);
                }
            }
        }
    }

    /**
     * Get the armor key.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param fastArmor krb fast armor
     */
    private void armorApRequest(KrbFastArmor fastArmor) throws KrbException {
        if (fastArmor.getArmorType() == ArmorType.ARMOR_AP_REQUEST) {
            ApReq apReq = KrbCodec.decode(fastArmor.getArmorValue(), ApReq.class);

            Ticket ticket = apReq.getTicket();
            EncryptionType encType = ticket.getEncryptedEncPart().getEType();
            EncryptionKey tgsKey = getTgsEntry().getKeys().get(encType);
            if (ticket.getTktvno() != KrbConstant.KRB_V5) {
                throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
            }

            EncTicketPart encPart = EncryptionUtil.unseal(ticket.getEncryptedEncPart(),
                    tgsKey, KeyUsage.KDC_REP_TICKET, EncTicketPart.class);
            ticket.setEncPart(encPart);

            EncryptionKey encKey = ticket.getEncPart().getKey();
            setSessionKey(encKey);

            Authenticator authenticator = EncryptionUtil.unseal(apReq.getEncryptedAuthenticator(),
                    encKey, KeyUsage.AP_REQ_AUTH, Authenticator.class);

            EncryptionKey armorKey = FastUtil.cf2(authenticator.getSubKey(), "subkeyarmor",
                    encKey, "ticketarmor");
            setArmorKey(armorKey);
        }
    }

    /**
     * Get tgs entry.
     *
     * @return TGS entry
     */
    public KrbIdentity getTgsEntry() {
        return tgsEntry;
    }

    /**
     * Set tgs entry .
     *
     * @param tgsEntry TGS entry
     */
    public void setTgsEntry(KrbIdentity tgsEntry) {
        this.tgsEntry = tgsEntry;
    }

    /**
     * Get whether is tcp.
     *
     * @return whether is tcp
     */
    public boolean isTcp() {
        return isTcp;
    }

    /**
     * Set use tcp.
     *
     * @param isTcp set kdc request though TCP protocol or not
     */
    public void isTcp(boolean isTcp) {
        this.isTcp = isTcp;
    }

    /**
     * Get the reply message.
     *
     * @return reply
     */
    public KrbMessage getReply() {
        return reply;
    }

    /**
     * Set kdc reply.
     *
     * @param reply reply
     */
    public void setReply(KdcRep reply) {
        this.reply = reply;
    }

    /**
     * Get client address.
     *
     * @return client address
     */
    public InetAddress getClientAddress() {
        return clientAddress;
    }

    /**
     * Set client address.
     *
     * @param clientAddress client address
     */
    public void setClientAddress(InetAddress clientAddress) {
        this.clientAddress = clientAddress;
    }

    /**
     * Get encryption type.
     *
     * @return encryption type
     */
    public EncryptionType getEncryptionType() {
        return encryptionType;
    }

    /**
     * Set encryption type.
     *
     * @param encryptionType encryption type
     */
    public void setEncryptionType(EncryptionType encryptionType) {
        this.encryptionType = encryptionType;
    }

    /**
     * Get ticket.
     *
     * @return ticket
     */
    public Ticket getTicket() {
        return ticket;
    }

    /**
     * Set ticket.
     *
     * @param ticket ticket
     */
    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

    /**
     * Get whether pre-authenticated.
     *
     * @return whether preauthenticated
     */
    public boolean isPreAuthenticated() {
        return isPreAuthenticated;
    }

    /**
     * Set whether pre-authenticated.
     *
     * @param isPreAuthenticated whether is preauthenticated
     */
    public void setPreAuthenticated(boolean isPreAuthenticated) {
        this.isPreAuthenticated = isPreAuthenticated;
    }

    /**
     * Get server entry.
     *
     * @return server entry
     */
    public KrbIdentity getServerEntry() {
        return serverEntry;
    }

    /**
     * Set server entry.
     *
     * @param serverEntry server entry
     */
    public void setServerEntry(KrbIdentity serverEntry) {
        this.serverEntry = serverEntry;
    }

    /**
     * Get client entry.
     *
     * @return client entry
     */
    public KrbIdentity getClientEntry() {
        return clientEntry;
    }

    /**
     * Set client entry.
     *
     * @param clientEntry client entry
     */
    public void setClientEntry(KrbIdentity clientEntry) {
        this.clientEntry = clientEntry;
    }

    /**
     * Get client key with entryption type.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param encType encryption type
     * @return encryption key
     */
    public EncryptionKey getClientKey(EncryptionType encType) throws KrbException {
        return getClientEntry().getKey(encType);
    }

    /**
     * Get client key.
     *
     * @return client key
     */
    public EncryptionKey getClientKey() {
        return clientKey;
    }

    /**
     * Set client key.
     *
     * @param clientKey client key
     */
    public void setClientKey(EncryptionKey clientKey) {
        this.clientKey = clientKey;
    }

    /**
     * Get server key.
     * @return The server key
     */
    public EncryptionKey getServerKey() {
        return serverKey;
    }

    /**
     * Set server key.
     *
     * @param serverKey server key
     */
    public void setServerKey(EncryptionKey serverKey) {
        this.serverKey = serverKey;
    }

    /**
     * Get tgs principal name.
     *
     * @return principal name
     */
    public PrincipalName getTgsPrincipal() {
        PrincipalName result = KrbUtil.makeTgsPrincipal(kdcContext.getKdcRealm());
        return result;
    }

    /**
     * Make reply.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    protected abstract void makeReply() throws KrbException;

    /**
     * Check Version.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    protected void checkVersion() throws KrbException {
        KdcReq request = getKdcReq();

        int kerberosVersion = request.getPvno();
        if (kerberosVersion != KrbConstant.KRB_V5) {
            LOG.warn("Kerberos version: " + kerberosVersion + " should equal to "
                    + KrbConstant.KRB_V5);
            throw new KrbException(KrbErrorCode.KDC_ERR_BAD_PVNO);
        }
    }

    /**
     * Check policy.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    protected void checkPolicy() throws KrbException {
        KrbIdentity entry = getClientEntry();

        // if we can not get the client entry, maybe it is token preauth, ignore it.
        if (entry != null) {
            if (entry.isDisabled()) {
                LOG.warn("Client entry " + entry.getPrincipalName() + " is disabled.");
                throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
            }
            if (entry.isLocked()) {
                LOG.warn("Client entry " + entry.getPrincipalName() + " is expired.");
                throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
            }
            if (entry.getExpireTime().lessThan(new Date().getTime())) {
                throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
            }
        } else {
            LOG.info("Client entry is empty.");
        }
    }

    /**
     * Check client.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    protected abstract void checkClient() throws KrbException;

    /**
     * Do the preatuh.
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    protected void preauth() throws KrbException {
        KdcReq request = getKdcReq();

        PaData preAuthData = request.getPaData();

        if (isPreauthRequired()) {
            if (isAnonymous && !isPkinit) {
                LOG.info("Need PKINIT.");
                KrbError krbError = makePreAuthenticationError(kdcContext, request,
                        KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED, true);
                throw new KdcRecoverableException(krbError);
            }

            if (preAuthData == null || preAuthData.isEmpty()) {
                LOG.info("The preauth data is empty.");
                KrbError krbError = makePreAuthenticationError(kdcContext, request,
                        KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED, false);
                throw new KdcRecoverableException(krbError);
            } else {
                getPreauthHandler().verify(this, preAuthData);
            }
        }

        setPreAuthenticated(true);
    }

    /**
     * Set whether preauth required.
     * @param preauthRequired whether preauthentication required
     */
    protected void setPreauthRequired(boolean preauthRequired) {
        preauthContext.setPreauthRequired(preauthRequired);
    }

    /**
     * Get whether preauth required.
     * @return whether preauthentication is required
     */
    protected boolean isPreauthRequired() {
        return preauthContext.isPreauthRequired();
    }

    /**
     * Get preauth handler.
     * @return preauthencation handler
     */
    protected PreauthHandler getPreauthHandler() {
        return kdcContext.getPreauthHandler();
    }

    /**
     * Check encryption type.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    protected void checkEncryptionType() throws KrbException {
        List<EncryptionType> requestedTypes = getKdcReq().getReqBody().getEtypes();

        EncryptionType bestType = EncryptionUtil.getBestEncryptionType(requestedTypes,
                kdcContext.getConfig().getEncryptionTypes());

        if (bestType == null) {
            LOG.error("Can't get the best encryption type.");
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP);
        }

        setEncryptionType(bestType);
    }

    /**
     * Do some authenticate.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    protected void authenticate() throws KrbException {
        checkEncryptionType();
        checkPolicy();
    }

    /**
     * Issue ticket.
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    protected abstract void issueTicket() throws KrbException;

    /**
     * Check server.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     */
    private void checkServer() throws KrbException {
        KdcReq request = getKdcReq();

        PrincipalName principal = request.getReqBody().getSname();
        String serverRealm = request.getReqBody().getRealm();
        if (serverRealm == null || serverRealm.isEmpty()) {
            LOG.info("Can't get the server realm from request, and try to get from kdcContext.");
            serverRealm = kdcContext.getKdcRealm();
        }
        principal.setRealm(serverRealm);

        KrbIdentity serverEntry = getEntry(principal.getName());
        setServerEntry(serverEntry);
        for (EncryptionType encType : request.getReqBody().getEtypes()) {
            if (serverEntry.getKeys().containsKey(encType)) {
                EncryptionKey serverKey = serverEntry.getKeys().get(encType);
                setServerKey(serverKey);
                break;
            }
        }
    }

    /**
     * Make preauthentication error.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param kdcContext kdc context
     * @param request kdc request
     * @param errorCode krb error code
     * @return The krb error reply to client
     */
    protected KrbError makePreAuthenticationError(KdcContext kdcContext, KdcReq request,
                                                  KrbErrorCode errorCode, boolean pkinit)
            throws KrbException {
        List<EncryptionType> encryptionTypes = kdcContext.getConfig().getEncryptionTypes();
        List<EncryptionType> clientEtypes = request.getReqBody().getEtypes();
        boolean isNewEtype = true;

        EtypeInfo2 eTypeInfo2 = new EtypeInfo2();

        EtypeInfo eTypeInfo = new EtypeInfo();

        for (EncryptionType encryptionType : encryptionTypes) {
            if (clientEtypes.contains(encryptionType)) {
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
        }

        byte[] encTypeInfo = null;
        byte[] encTypeInfo2 = null;
        if (!isNewEtype) {
            encTypeInfo = KrbCodec.encode(eTypeInfo);
        }
        encTypeInfo2 = KrbCodec.encode(eTypeInfo2);

        MethodData methodData = new MethodData();
        //methodData.add(new PaDataEntry(PaDataType.ENC_TIMESTAMP, null));
        if (!isNewEtype) {
            methodData.add(new PaDataEntry(PaDataType.ETYPE_INFO, encTypeInfo));
        }
        methodData.add(new PaDataEntry(PaDataType.ETYPE_INFO2, encTypeInfo2));

        if (pkinit) {
            methodData.add(new PaDataEntry(PaDataType.PK_AS_REQ, "empty".getBytes()));
            methodData.add(new PaDataEntry(PaDataType.PK_AS_REP, "empty".getBytes()));
        }

        KrbError krbError = new KrbError();
        krbError.setErrorCode(errorCode);
        byte[] encodedData = KrbCodec.encode(methodData);
        krbError.setEdata(encodedData);

        return krbError;
    }

    /**
     * Get identity entry with principal name.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @param principal Principal
     * @return krb identity entry
     */
    protected KrbIdentity getEntry(String principal) throws KrbException {
        KrbIdentity entry;
        entry = kdcContext.getIdentityService().getIdentity(principal);
        return entry;
    }

    /**
     * Get request body.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @return request body
     */
    protected ByteBuffer getRequestBody() throws KrbException {
        return null;
    }

    /**
     * Get armor key.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e
     * @return armor key
     */
    public EncryptionKey getArmorKey() throws KrbException {
        return fastContext.getArmorKey();
    }

    /**
     * Set armor key.
     *
     * @param armorKey armor key
     */
    protected void setArmorKey(EncryptionKey armorKey) {
        fastContext.setArmorKey(armorKey);
    }

    /**
     * Get client principal.
     * @return client principal
     */
    public PrincipalName getClientPrincipal() {
        return clientPrincipal;
    }

    /**
     * Set client principal.
     * @param clientPrincipal client principal
     */
    public void setClientPrincipal(PrincipalName clientPrincipal) {
        this.clientPrincipal = clientPrincipal;
    }

    /**
     * Get server principal.
     * @return server principal
     */
    public PrincipalName getServerPrincipal() {
        return serverPrincipal;
    }

    /**
     * Set server principal.
     * @param serverPrincipal server principal
     */
    public void setServerPrincipal(PrincipalName serverPrincipal) {
        this.serverPrincipal = serverPrincipal;
    }

    /**
     * Get innerbodyout.
     * @return inner body out
     */
    protected byte[] getInnerBodyout() {
        return innerBodyout;
    }

    /**
     * Get whether kdc request with token.
     * @return whether isToken
     */
    protected boolean isToken() {
        return isToken;
    }

    /**
     * Set auth token.
     * @param authToken The auth token
     */
    public void setToken(AuthToken authToken) {
        this.token = authToken;
    }

    /**
     * Get auth token.
     * @return token
     */
    protected AuthToken getToken() {
        return token;
    }

    protected boolean isPkinit() {
        return isPkinit;
    }

    public boolean isAnonymous() {
        return getKdcOptions().isFlagSet(KdcOption.REQUEST_ANONYMOUS);
    }

    public KdcOptions getKdcOptions() {
        return kdcReq.getReqBody().getKdcOptions();
    }

    public void setReqPackage(ByteBuffer reqPackage) {
        this.reqPackage = reqPackage;
    }

    public ByteBuffer getReqPackage() {
        return this.reqPackage;
    }
}
