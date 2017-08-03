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
package org.apache.kerby.kerberos.kerb.gss.impl;

import com.sun.security.jgss.InquireType;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.gss.GssMechFactory;
import org.apache.kerby.kerberos.kerb.gss.KerbyGssProvider;
import org.apache.kerby.kerberos.kerb.request.ApRequest;
import org.apache.kerby.kerberos.kerb.response.ApResponse;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.ap.ApRep;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlags;
import org.ietf.jgss.ChannelBinding;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.spi.GSSContextSpi;
import sun.security.jgss.spi.GSSCredentialSpi;
import sun.security.jgss.spi.GSSNameSpi;

import javax.security.auth.kerberos.KerberosTicket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.Provider;

@SuppressWarnings("PMD")
public class GssContext implements GSSContextSpi {

    private static final int STATE_NONE = 0;
    private static final int STATE_ESTABLISHING = 1;
    private static final int STATE_ESTABLISHED = 2;
    private static final int STATE_DESTROYED = 3;

    private static final byte[] MSG_AP_REQ = {(byte) 0x1, (byte) 0};
    private static final byte[] MSG_AP_REP = {(byte) 0x2, (byte) 0};

    private int ctxState = STATE_NONE;

    private final GSSCaller caller;
    private GssCredElement myCred;
    private boolean initiator;
    private GssNameElement myName;
    private GssNameElement peerName;
    private int lifeTime;
    private ChannelBinding channelBinding;

    private boolean mutualAuth  = true;
    private boolean replayDet  = true;
    private boolean sequenceDet  = true;
    private boolean credDeleg  = false;
    private boolean confState  = true;
    private boolean integState  = true;
    private boolean delegPolicy = false;

    public static final int INVALID_KEY = 0;
    public static final int SESSION_KEY = 1;
    public static final int INITIATOR_SUBKEY = 2;
    public static final int ACCEPTOR_SUBKEY = 4;
    private int keyComesFrom = INVALID_KEY;

    private EncryptionKey sessionKey;   // used between client and app server
    private TicketFlags ticketFlags;
    private ApReq outApReq;

    private GssEncryptor gssEncryptor;

    // Called on initiator's side.
    public GssContext(GSSCaller caller, GssNameElement peerName, GssCredElement myCred,
                      int lifeTime)
            throws GSSException {
        if (peerName == null) {
            throw new IllegalArgumentException("Cannot have null peer name");
        }

        this.caller = caller;
        this.peerName = peerName;
        this.myCred = myCred;
        this.lifeTime = lifeTime;
        this.initiator = true;

        mySequenceNumberLock = new Object();
        peerSequenceNumberLock = new Object();
    }

    public GssContext(GSSCaller caller, GssAcceptCred myCred)
            throws GSSException {
        this.caller = caller;
        this.myCred = myCred;
        this.initiator = false;

        mySequenceNumberLock = new Object();
        peerSequenceNumberLock = new Object();
    }

    public GssContext(GSSCaller caller, byte[] interProcessToken)
            throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE, -1, "Unsupported feature");
    }

    public Provider getProvider() {
        return new KerbyGssProvider();
    }

    public void requestLifetime(int lifeTime) throws GSSException {
        if (ctxState == STATE_NONE && isInitiator()) {
            this.lifeTime = lifeTime;
        }
    }

    public void requestMutualAuth(boolean state) throws GSSException {
        if (ctxState == STATE_NONE && isInitiator()) {
            mutualAuth  = state;
        }
    }

    public void requestReplayDet(boolean state) throws GSSException {
        if (ctxState == STATE_NONE && isInitiator()) {
            replayDet = state;
        }
    }

    public void requestSequenceDet(boolean state) throws GSSException {
        if (ctxState == STATE_NONE && isInitiator()) {
            replayDet = state;
        }
    }

    public void requestCredDeleg(boolean state) throws GSSException {
        if (ctxState == STATE_NONE && isInitiator() && myCred == null) {
            credDeleg  = state;
        }
    }

    public void requestAnonymity(boolean state) throws GSSException {
        // anonymous context not supported
    }

    public void requestConf(boolean state) throws GSSException {
        if (ctxState == STATE_NONE && isInitiator()) {
            confState = state;
        }
    }

    public void requestInteg(boolean state) throws GSSException {
        if (ctxState == STATE_NONE && isInitiator()) {
            integState = state;
        }
    }

    public void requestDelegPolicy(boolean state) throws GSSException {
        if (ctxState == STATE_NONE && isInitiator()) {
            delegPolicy = state;
        }
    }

    public void setChannelBinding(ChannelBinding cb) throws GSSException {
        this.channelBinding = cb;
    }

    public boolean getCredDelegState() {
        return credDeleg;
    }

    public boolean getMutualAuthState() {
        return mutualAuth;
    }

    public boolean getReplayDetState() {
        return replayDet || sequenceDet;
    }

    public boolean getSequenceDetState() {
        return sequenceDet;
    }

    public boolean getAnonymityState() {
        return false;
    }

    public boolean getDelegPolicyState() {
        return delegPolicy;
    }

    public boolean isTransferable() throws GSSException {
        return false;
    }

    public boolean isProtReady() {
        return ctxState == STATE_ESTABLISHED;
    }

    public boolean isInitiator() {
        return initiator;
    }

    public boolean getConfState() {
        return confState;
    }

    public boolean getIntegState() {
        return integState;
    }

    public int getLifetime() {
        return GSSContext.INDEFINITE_LIFETIME;
    }

    public boolean isEstablished() {
        return ctxState == STATE_ESTABLISHED;
    }

    public GSSNameSpi getSrcName() throws GSSException {
        return isInitiator() ? myName : peerName;
    }

    public GSSNameSpi getTargName() throws GSSException {
        return !isInitiator() ? myName : peerName;
    }

    public Oid getMech() throws GSSException {
        return GssMechFactory.getOid();
    }

    public GSSCredentialSpi getDelegCred() throws GSSException {
        throw new GSSException(GSSException.FAILURE, -1, "API not implemented");  // TODO:
    }

    public byte[] initSecContext(InputStream is, int mechTokenSize)
            throws GSSException {
        if (!isInitiator()) {
            throw new GSSException(GSSException.FAILURE, -1, "initSecContext called on acceptor");
        }

        byte[] ret = null;

        if (ctxState == STATE_NONE) {

            if (!myCred.isInitiatorCredential()) {
                throw new GSSException(GSSException.NO_CRED, -1, "No TGT available");
            }

            // check if service ticket already exists
            // if not, prepare to get it through TGS_REQ
            SgtTicket sgtTicket = null;
            String serviceName = peerName.getPrincipalName().getName();
            myName = (GssNameElement) myCred.getName();
            PrincipalName clientPrincipal = myName.getPrincipalName();

            sgtTicket = GssUtil.getSgtCredentialFromContext(caller, clientPrincipal.getName(), serviceName);

            if (sgtTicket == null) {
                sgtTicket = GssUtil.applySgtCredential(((GssInitCred) myCred).getKerberosTicket(), serviceName);

                // add this service credential to context
                final KerberosTicket ticket =
                        GssUtil.convertKrbTicketToKerberosTicket(sgtTicket, myName.getPrincipalName().getName());
                CredUtils.addCredentialToSubject(ticket);
            }

            ApRequest apRequest = new ApRequest(clientPrincipal, sgtTicket);
            try {
                outApReq = apRequest.getApReq();
            } catch (KrbException e) {
                throw new GSSException(GSSException.FAILURE, -1, "Generate ApReq failed: " + e.getMessage());
            }
            setupInitiatorContext(sgtTicket, apRequest);
            try {
                ByteBuffer outBuffer = ByteBuffer.allocate(outApReq.encodingLength() + 2);
                outBuffer.put(MSG_AP_REQ);
                outApReq.encode(outBuffer);
                outBuffer.flip();
                ret = outBuffer.array();
            } catch (IOException e) {
                throw new GSSException(GSSException.FAILURE, -1, "Generate ApReq bytes failed: " + e.getMessage());
            }

            ctxState = STATE_ESTABLISHING;
            if (!getMutualAuthState()) {
                gssEncryptor = new GssEncryptor(getSessionKey());
                ctxState = STATE_ESTABLISHED;
            }

        } else if (ctxState == STATE_ESTABLISHING) {
            verifyServerToken(is, mechTokenSize);
            gssEncryptor = new GssEncryptor(getSessionKey());
            outApReq = null;
            ctxState = STATE_ESTABLISHED;
        }
        return ret;
    }

    private void setupInitiatorContext(SgtTicket sgt, ApRequest apRequest) throws GSSException {
        EncKdcRepPart encKdcRepPart = sgt.getEncKdcRepPart();
        TicketFlags ticketFlags = encKdcRepPart.getFlags();
        setTicketFlags(ticketFlags);

        setAuthTime(encKdcRepPart.getAuthTime().toString());

        Authenticator auth;
        try {
            auth = apRequest.getApReq().getAuthenticator();
        } catch (KrbException e) {
            throw new GSSException(GSSException.FAILURE, -1, "ApReq failed in Initiator");
        }
        setMySequenceNumber(auth.getSeqNumber());

        EncryptionKey subKey = auth.getSubKey();
        if (subKey != null) {
            setSessionKey(subKey, GssContext.INITIATOR_SUBKEY);
        } else {
            setSessionKey(sgt.getSessionKey(), GssContext.SESSION_KEY);
        }

        if (!getMutualAuthState()) {
            setPeerSequenceNumber(0);
        }
    }

    /**
     * Verify the AP_REP from server and set context accordingly
     * @param is
     * @param mechTokenSize
     * @return
     * @throws GSSException
     * @throws IOException
     */
    private void verifyServerToken(InputStream is, int mechTokenSize)
            throws GSSException {
        byte[] token;
        ApRep apRep;
        try {
            if (!(is.read() == MSG_AP_REP[0] && is.read() == MSG_AP_REP[1])) {
                throw new GSSException(GSSException.FAILURE, -1, "Invalid ApRep message ID");
            }
            token = new byte[mechTokenSize - MSG_AP_REP.length];
            is.read(token);
            apRep = new ApRep();
            apRep.decode(token);
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, "Invalid ApRep " + e.getMessage());
        }

        try {
            ApResponse.validate(getSessionKey(), apRep, outApReq);
        } catch (KrbException e) {
            throw new GSSException(GSSException.UNAUTHORIZED, -1, "ApRep verification failed");
        }

        EncryptionKey key = apRep.getEncRepPart().getSubkey();
        if (key != null) {
            setSessionKey(key, ACCEPTOR_SUBKEY);
        }

        int seqNum = apRep.getEncRepPart().getSeqNumber();
        setPeerSequenceNumber(seqNum == -1 ? 0 : seqNum);
    }

    public byte[] acceptSecContext(InputStream is, int mechTokenSize)
            throws GSSException {
        byte[] ret = null;

        if (isInitiator()) {
            throw new GSSException(GSSException.FAILURE, -1, "acceptSecContext called on initiator");
        }

        if (ctxState == STATE_NONE) {
            ctxState = STATE_ESTABLISHING;
            if (!myCred.isAcceptorCredential()) {
                throw new GSSException(GSSException.FAILURE, -1, "No acceptor credential available");
            }

            GssAcceptCred acceptCred = (GssAcceptCred) myCred;
            CredUtils.checkPrincipalPermission(
                    ((GssNameElement) acceptCred.getName()).getPrincipalName().getName(), "accept");

            if (getMutualAuthState()) {
                ret = verifyClientToken(acceptCred, is, mechTokenSize);
            }

            gssEncryptor = new GssEncryptor(getSessionKey());

            myCred = null;
            ctxState = STATE_ESTABLISHED;
        }

        return ret;
    }

    private byte[] verifyClientToken(GssAcceptCred acceptCred, InputStream is, int mechTokenSize)
            throws GSSException {
        byte[] token;
        ApReq apReq;
        try {
            if (!(is.read() == MSG_AP_REQ[0] && is.read() == MSG_AP_REQ[1])) {
                throw new GSSException(GSSException.FAILURE, -1, "Invalid ApReq message ID");
            }

            token = new byte[mechTokenSize - MSG_AP_REQ.length];
            is.read(token);
            apReq = new ApReq();
            apReq.decode(token);
        } catch (IOException e) {
            throw new GSSException(GSSException.UNAUTHORIZED, -1, "ApReq invalid:" + e.getMessage());
        }

        int kvno = apReq.getTicket().getEncryptedEncPart().getKvno();
        int encryptType = apReq.getTicket().getEncryptedEncPart().getEType().getValue();

        EncryptionKey serverKey = acceptCred.getEncryptionKey(encryptType, kvno);
        if (serverKey == null) {
            throw new GSSException(GSSException.FAILURE, -1, "Server key not found");
        }
        peerName = (GssNameElement) acceptCred.getName();

        try {
            ApRequest.validate(serverKey, apReq,
                    channelBinding == null ? null : channelBinding.getInitiatorAddress(), 5 * 60 * 1000);
        } catch (KrbException e) {
            throw new GSSException(GSSException.UNAUTHORIZED, -1, "ApReq verification failed: " + e.getMessage());
        }

        ApResponse apResponse = new ApResponse(apReq);
        ApRep apRep;
        try {
            apRep = apResponse.getApRep();
        } catch (KrbException e) {
            throw new GSSException(GSSException.UNAUTHORIZED, -1, "Generate ApRep failed");
        }

        EncTicketPart apReqTicketEncPart = apReq.getTicket().getEncPart();

        EncryptionKey ssKey = apReqTicketEncPart.getKey();
        Authenticator auth = apReq.getAuthenticator();
        EncryptionKey subKey = auth.getSubKey();

        if (subKey != null) {
            setSessionKey(subKey, INITIATOR_SUBKEY);
        } else {
            setSessionKey(ssKey, SESSION_KEY);
        }

        // initial seqNumber
        int seqNumber = auth.getSeqNumber();
        setMySequenceNumber(seqNumber);
        // initial authtime, tktflags, authdata,
        setAuthTime(apReqTicketEncPart.getAuthTime().toString());
        setTicketFlags(apReqTicketEncPart.getFlags());
        setAuthData(apReqTicketEncPart.getAuthorizationData());

        byte[] ret = null;
        try {
            ByteBuffer outBuffer = ByteBuffer.allocate(apRep.encodingLength() + 2);
            outBuffer.put(MSG_AP_REP);
            apRep.encode(outBuffer);
            outBuffer.flip();
            ret = outBuffer.array();
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, "Generate ApRep bytes failed:" + e.getMessage());
        }
        return ret;
    }

    public int getWrapSizeLimit(int qop, boolean confReq, int maxTokSize)
            throws GSSException {
        if (gssEncryptor.isV2()) {
            return WrapTokenV2.getMsgSizeLimit(qop, confReq, maxTokSize, gssEncryptor);
        } else {
            return WrapTokenV1.getMsgSizeLimit(qop, confReq, maxTokSize, gssEncryptor);
        }
    }

    public void wrap(InputStream is, OutputStream os, MessageProp msgProp)
            throws GSSException {
        if (ctxState != STATE_ESTABLISHED) {
            throw new GSSException(GSSException.NO_CONTEXT, -1, "Context invalid for wrap");
        }

        int len;
        byte[] inBuf;
        try {
            len = is.available();
            inBuf = new byte[len];
            is.read(inBuf);
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, "Error when get user data:" + e.getMessage());
        }
        if (gssEncryptor.isV2()) {
            WrapTokenV2 token = new WrapTokenV2(this, inBuf, 0, len, msgProp);
            token.wrap(os);
        } else {
            WrapTokenV1 token = new WrapTokenV1(this, inBuf, 0, len, msgProp);
            token.wrap(os);
        }
    }

    public byte[] wrap(byte[] inBuf, int offset, int len,
                       MessageProp msgProp) throws GSSException {
        if (ctxState != STATE_ESTABLISHED) {
            throw new GSSException(GSSException.NO_CONTEXT, -1, "Context invalid for wrap");
        }
        byte[] ret;
        if (gssEncryptor.isV2()) {
            WrapTokenV2 token = new WrapTokenV2(this, inBuf, offset, len, msgProp);
            ret = token.wrap();
        } else {
            WrapTokenV1 token = new WrapTokenV1(this, inBuf, offset, len, msgProp);
            ret = token.wrap();
        }
        return ret;
    }

    public void unwrap(InputStream is, OutputStream os,
                       MessageProp msgProp) throws GSSException {
        if (ctxState != STATE_ESTABLISHED) {
            throw new GSSException(GSSException.NO_CONTEXT, -1, "Context invalid for unwrap");
        }

        if (gssEncryptor.isV2()) {
            WrapTokenV2 token = new WrapTokenV2(this, msgProp, is);
            token.unwrap(os);
        } else {
            WrapTokenV1 token = new WrapTokenV1(this, msgProp, is);
            token.unwrap(os);
        }
    }

    public byte[] unwrap(byte[] inBuf, int offset, int len,
                         MessageProp msgProp) throws GSSException {
        if (ctxState != STATE_ESTABLISHED) {
            throw new GSSException(GSSException.NO_CONTEXT, -1, "Context invalid for unwrap");
        }

        byte[] ret;
        if (gssEncryptor.isV2()) {
            WrapTokenV2 token = new WrapTokenV2(this, msgProp, inBuf, offset, len);
            ret = token.unwrap();
        } else {
            WrapTokenV1 token = new WrapTokenV1(this, msgProp, inBuf, offset, len);
            ret = token.unwrap();
        }
        return ret;
    }

    public void getMIC(InputStream is, OutputStream os,
                       MessageProp msgProp) throws GSSException {
        if (ctxState != STATE_ESTABLISHED) {
            throw new GSSException(GSSException.NO_CONTEXT, -1, "Context invalid for getMIC");
        }

        try {
            int len = is.available();
            byte[] inMsg = new byte[len];
            is.read(inMsg);
            if (gssEncryptor.isV2()) {
                MicTokenV2 token = new MicTokenV2(this, inMsg, 0, len, msgProp);
                token.getMic(os);
            } else {
                MicTokenV1 token = new MicTokenV1(this, inMsg, 0, len, msgProp);
                token.getMic(os);
            }
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, "Error when get user data in getMIC:" + e.getMessage());
        }
    }

    public byte[] getMIC(byte[] inMsg, int offset, int len,
                         MessageProp msgProp) throws GSSException {
        if (ctxState != STATE_ESTABLISHED) {
            throw new GSSException(GSSException.NO_CONTEXT, -1, "Context invalid for getMIC");
        }

        byte[] ret;
        if (gssEncryptor.isV2()) {
            MicTokenV2 token = new MicTokenV2(this, inMsg, offset, len, msgProp);
            ret = token.getMic();
        } else {
            MicTokenV1 token = new MicTokenV1(this, inMsg, offset, len, msgProp);
            ret = token.getMic();
        }
        return ret;
    }

    public void verifyMIC(InputStream is, InputStream msgStr,
                          MessageProp msgProp) throws GSSException {
        if (ctxState != STATE_ESTABLISHED) {
            throw new GSSException(GSSException.NO_CONTEXT, -1, "Context invalid for verifyMIC");
        }

        try {
            int tokLen = is.available();
            byte[] inTok = new byte[tokLen];
            int msgLen = msgStr.available();
            byte[] inMsg = new byte[msgLen];

           verifyMIC(inTok, 0, tokLen, inMsg, 0, msgLen, msgProp);
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1,
                    "Error when get user data in verifyMIC:" + e.getMessage());
        }
    }

    public void verifyMIC(byte[]inTok, int tokOffset, int tokLen,
                          byte[] inMsg, int msgOffset, int msgLen,
                          MessageProp msgProp) throws GSSException {
        if (ctxState != STATE_ESTABLISHED) {
            throw new GSSException(GSSException.NO_CONTEXT, -1, "Context invalid for verifyMIC");
        }

        if (gssEncryptor.isV2()) {
            MicTokenV2 token = new MicTokenV2(this, msgProp, inTok, tokOffset, tokLen);
            token.verify(inMsg, msgOffset, msgLen);
        } else {
            MicTokenV1 token = new MicTokenV1(this, msgProp, inTok, tokOffset, tokLen);
            token.verify(inMsg, msgOffset, msgLen);
        }
    }

    public byte[] export() throws GSSException {
        throw new GSSException(GSSException.UNAVAILABLE, -1, "Unsupported export() method");
    }

    public void dispose() throws GSSException {
        ctxState = STATE_DESTROYED;
        setSessionKey(null, 0);
        peerName = null;
        myCred = null;
        myName = null;
    }


    private String authTime;
    private void setAuthTime(String authTime) {
        this.authTime = authTime;
    }

    public Object inquireSecContext(InquireType type) throws GSSException {
        if (ctxState != STATE_ESTABLISHED) {
            throw new GSSException(GSSException.NO_CONTEXT, -1, "Invalid context");
        }

        switch (type) {
            case KRB5_GET_SESSION_KEY:
                return getSessionKey();
            case KRB5_GET_TKT_FLAGS:
                return GssUtil.ticketFlagsToBooleans(ticketFlags);
            case KRB5_GET_AUTHZ_DATA:
                if (isInitiator()) {
                    throw new GSSException(GSSException.UNAVAILABLE, -1,
                            "Authorization data not available for initiator");
                } else {
                    return GssUtil.kerbyAuthorizationDataToJgssAuthorizationDataEntries(authData);
                }
            case KRB5_GET_AUTHTIME:
                return authTime;
        }
        throw new GSSException(GSSException.UNAVAILABLE, -1, "Unsupported inquire type");
    }


    // functions not belong to SPI
    private void setSessionKey(EncryptionKey encryptionKey, int keyComesFrom) {
        this.sessionKey = encryptionKey;
        this.keyComesFrom = keyComesFrom;
    }

    public int getKeyComesFrom() {
        return keyComesFrom;
    }

    private EncryptionKey getSessionKey() {
        return sessionKey;
    }

    private void setTicketFlags(TicketFlags ticketFlags) {
        this.ticketFlags = ticketFlags;
    }

    private AuthorizationData authData;
    private void setAuthData(AuthorizationData authData) {
        this.authData = authData;
    }


    private int mySequenceNumber;
    private int peerSequenceNumber;
    private Object mySequenceNumberLock;
    private Object peerSequenceNumberLock;

    public void setMySequenceNumber(int sequenceNumber) {
        synchronized (mySequenceNumberLock) {
            mySequenceNumber = sequenceNumber;
        }
    }

    public int incMySequenceNumber() {
        synchronized (mySequenceNumberLock) {
            return mySequenceNumber++;
        }
    }

    public void setPeerSequenceNumber(int sequenceNumber) {
        synchronized (peerSequenceNumberLock) {
            peerSequenceNumber = sequenceNumber;
        }
    }

    public int incPeerSequenceNumber() {
        synchronized (peerSequenceNumberLock) {
            return peerSequenceNumber++;
        }
    }

    public GssEncryptor getGssEncryptor() {
        return gssEncryptor;
    }
}

