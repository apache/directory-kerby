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
package org.apache.kerby.kerberos.kerb.client.request;

import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOptions;
import org.apache.kerby.kerberos.kerb.client.preauth.FastContext;
import org.apache.kerby.kerberos.kerb.client.preauth.PreauthContext;
import org.apache.kerby.kerberos.kerb.client.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.common.*;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcOptions;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerby.transport.Transport;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A wrapper for KdcReq request
 */
public abstract class KdcRequest {
    private KrbContext context;
    private Transport transport;

    private KrbOptions krbOptions;
    private PrincipalName serverPrincipal;
    private List<HostAddress> hostAddresses = new ArrayList<HostAddress>();
    private KdcOptions kdcOptions = new KdcOptions();
    private List<EncryptionType> encryptionTypes;
    private EncryptionType chosenEncryptionType;
    private int chosenNonce;
    private KdcReq kdcReq;
    private KdcRep kdcRep;
    protected Map<String, Object> credCache;
    private PreauthContext preauthContext;
    private FastContext fastContext;
    private EncryptionKey asKey;

    private KrbError errorReply;
    private boolean isRetrying;

    public KdcRequest(KrbContext context) {
        this.context = context;
        this.isRetrying = false;
        this.credCache = new HashMap<String, Object>();
        this.preauthContext = context.getPreauthHandler()
                .preparePreauthContext(this);
        this.fastContext = new FastContext();
    }

    public void setTransport(Transport transport) {
        this.transport = transport;
    }

    public Transport getTransport() {
        return this.transport;
    }

    public void setKrbOptions(KrbOptions options) {
        this.krbOptions = options;
    }

    public KrbOptions getKrbOptions() {
        return krbOptions;
    }

    public boolean isRetrying() {
        return isRetrying;
    }

    public void setAsKey(EncryptionKey asKey) {
        this.asKey = asKey;
    }

    public EncryptionKey getAsKey() throws KrbException {
        return asKey;
    }

    public void setAllowedPreauth(PaDataType paType) {
        preauthContext.setAllowedPaType(paType);
    }

    public Map<String, Object> getCredCache() {
        return credCache;
    }

    public void setPreauthRequired(boolean preauthRequired) {
        preauthContext.setPreauthRequired(preauthRequired);
    }

    public PreauthContext getPreauthContext() {
        return preauthContext;
    }

    protected void loadCredCache() {
        // TODO
    }

    public KdcReq getKdcReq() {
        return kdcReq;
    }

    public void setKdcReq(KdcReq kdcReq) {
        this.kdcReq = kdcReq;
    }

    public KdcRep getKdcRep() {
        return kdcRep;
    }

    public void setKdcRep(KdcRep kdcRep) {
        this.kdcRep = kdcRep;
    }

    protected KdcReqBody makeReqBody() throws KrbException {
        KdcReqBody body = new KdcReqBody();

        long startTime = System.currentTimeMillis();
        body.setFrom(new KerberosTime(startTime));

        PrincipalName cName = null;
        cName = getClientPrincipal();
        body.setCname(cName);

        body.setRealm(cName.getRealm());

        PrincipalName sName = getServerPrincipal();
        body.setSname(sName);

        body.setTill(new KerberosTime(startTime + getTicketValidTime()));

        int nonce = generateNonce();
        body.setNonce(nonce);
        setChosenNonce(nonce);

        body.setKdcOptions(getKdcOptions());

        HostAddresses addresses = getHostAddresses();
        if (addresses != null) {
            body.setAddresses(addresses);
        }

        body.setEtypes(getEncryptionTypes());

        return body;
    }

    public KdcOptions getKdcOptions() {
        return kdcOptions;
    }

    public HostAddresses getHostAddresses() {
        HostAddresses addresses = null;
        if (!hostAddresses.isEmpty()) {
            addresses = new HostAddresses();
            for(HostAddress ha : hostAddresses) {
                addresses.addElement(ha);
            }
        }
        return addresses;
    }

    public KrbContext getContext() {
        return context;
    }

    protected byte[] decryptWithClientKey(EncryptedData data, KeyUsage usage) throws KrbException {
        return EncryptionHandler.decrypt(data, getClientKey(), usage);
    }

    public void setContext(KrbContext context) {
        this.context = context;
    }

    public void setHostAddresses(List<HostAddress> hostAddresses) {
        this.hostAddresses = hostAddresses;
    }

    public void setKdcOptions(KdcOptions kdcOptions) {
        this.kdcOptions = kdcOptions;
    }

    public abstract PrincipalName getClientPrincipal();

    public PrincipalName getServerPrincipal() {
        return serverPrincipal;
    }

    public void setServerPrincipal(PrincipalName serverPrincipal) {
        this.serverPrincipal = serverPrincipal;
    }

    public List<EncryptionType> getEncryptionTypes() {
        if (encryptionTypes == null) {
            encryptionTypes = context.getConfig().getEncryptionTypes();
        }
        return encryptionTypes;
    }

    public void setEncryptionTypes(List<EncryptionType> encryptionTypes) {
        this.encryptionTypes = encryptionTypes;
    }

    public EncryptionType getChosenEncryptionType() {
        return chosenEncryptionType;
    }

    public void setChosenEncryptionType(EncryptionType chosenEncryptionType) {
        this.chosenEncryptionType = chosenEncryptionType;
    }

    public int generateNonce() {
        return context.generateNonce();
    }

    public int getChosenNonce() {
        return chosenNonce;
    }

    public void setChosenNonce(int nonce) {
        this.chosenNonce = nonce;
    }

    public abstract EncryptionKey getClientKey() throws KrbException;

    public long getTicketValidTime() {
        return context.getTicketValidTime();
    }

    public KerberosTime getTicketTillTime() {
        long now = System.currentTimeMillis();
        return new KerberosTime(now + KerberosTime.MINUTE * 60 * 1000);
    }

    public void addHost(String hostNameOrIpAddress) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(hostNameOrIpAddress);
        hostAddresses.add(new HostAddress(address));
    }

    public void process() throws KrbException {
        preauth();
    }

    public abstract void processResponse(KdcRep kdcRep) throws KrbException;

    public KrbOptions getPreauthOptions() {
        return new KrbOptions();
    }

    protected void preauth() throws KrbException {
        loadCredCache();

        List<EncryptionType> etypes = getEncryptionTypes();
        if (etypes.isEmpty()) {
            throw new KrbException("No encryption type is configured and available");
        }
        EncryptionType encryptionType = etypes.iterator().next();
        setChosenEncryptionType(encryptionType);

        getPreauthHandler().preauth(this);
    }

    protected PreauthHandler getPreauthHandler() {
        return getContext().getPreauthHandler();
    }

    /**
     * Indicate interest in the AS key.
     */
    public void needAsKey() throws KrbException {
        EncryptionKey clientKey = getClientKey();
        if (clientKey == null) {
            throw new RuntimeException("Client key should be prepared or prompted at this time!");
        }
        setAsKey(clientKey);
    }

    /**
     * Get the enctype expected to be used to encrypt the encrypted portion of
     * the AS_REP packet.  When handling a PREAUTH_REQUIRED error, this
     * typically comes from etype-info2.  When handling an AS reply, it is
     * initialized from the AS reply itself.
     */
    public EncryptionType getEncType() {

        return getChosenEncryptionType();
    }

    public void askQuestion(String question, String challenge) {
        preauthContext.getUserResponser().askQuestion(question, challenge);
    }

    /**
     * Get a pointer to the FAST armor key, or NULL if the client is not using FAST.
     */
    public EncryptionKey getArmorKey() {
        return fastContext.armorKey;
    }

    /**
     * Get the current time for use in a preauth response.  If
     * allow_unauth_time is true and the library has been configured to allow
     * it, the current time will be offset using unauthenticated timestamp
     * information received from the KDC in the preauth-required error, if one
     * has been received.  Otherwise, the timestamp in a preauth-required error
     * will only be used if it is protected by a FAST channel.  Only set
     * allow_unauth_time if using an unauthenticated time offset would not
     * create a security issue.
     */
    public KerberosTime getPreauthTime() {
        return KerberosTime.now();
    }

    /**
     * Get a state item from an input ccache, which may allow it
     * to retrace the steps it took last time.  The returned data string is an
     * alias and should not be freed.
     */
    public Object getCacheValue(String key) {
        return credCache.get(key);
    }

    /**
     * Set a state item which will be recorded to an output
     * ccache, if the calling application supplied one.  Both key and data
     * should be valid UTF-8 text.
     */
    public void cacheValue(String key, Object value) {
        credCache.put(key, value);
    }
}
