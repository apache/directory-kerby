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

import org.apache.kerby.kerberos.kerb.*;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.preauth.KdcFastContext;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthContext;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.spec.base.*;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Date;
import java.util.List;

public abstract class KdcRequest {

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

    public KdcReq getKdcReq() {
        return kdcReq;
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
        PrincipalName result = KrbUtil.makeTgsPrincipal(kdcContext.getKdcRealm());
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

    protected abstract void checkClient() throws KrbException;

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

    protected abstract void issueTicket() throws KrbException;

    private void checkServer() throws KrbException {
        KdcReq request = getKdcReq();

        KrbIdentity tgsEntry = getEntry(getTgsPrincipal().getName());
        setTgsEntry(tgsEntry);

        PrincipalName principal = request.getReqBody().getSname();
        String serverRealm = request.getReqBody().getRealm();
        if (serverRealm == null || serverRealm.isEmpty()) {
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
