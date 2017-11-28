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
package org.apache.kerby.has.server.kdc;

import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.has.server.HasServer;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.KdcRecoverableException;
import org.apache.kerby.kerberos.kerb.server.KdcServer;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.server.request.AsRequest;
import org.apache.kerby.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.HostAddress;
import org.apache.kerby.kerberos.kerb.type.base.HostAddresses;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbToken;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.base.TokenFormat;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOption;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOptions;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.token.PaTokenRequest;
import org.apache.kerby.kerberos.kerb.type.pa.token.TokenInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class HasKdcHandler {
    private static final Logger LOG = LoggerFactory.getLogger(HasKdcHandler.class);

    private KdcContext kdcContext;
    private KrbContext krbContext;
    private KdcServer kdcServer;

    /**
     * Constructor with has server.
     *
     * @param hasServer has server
     */
    public HasKdcHandler(HasServer hasServer) {
        this.krbContext = new KrbContext();
        this.krbContext.init(hasServer.getKrbSetting());
        this.kdcServer = hasServer.getKdcServer();
        prepareHandler(kdcServer);
    }

    public KrbContext getKrbContext() {
        return krbContext;
    }

    public KdcContext getKdcContext() {
        return kdcContext;
    }

    private KdcServer getKdcServer() {
        return kdcServer;
    }

    private void prepareHandler(KdcServer kdcServer) {
        this.kdcContext = new KdcContext(kdcServer.getKdcSetting());
        this.kdcContext.setIdentityService(kdcServer.getIdentityService());
        PreauthHandler preauthHandler = new PreauthHandler();
        preauthHandler.init();
        this.kdcContext.setPreauthHandler(preauthHandler);
    }

    private String getAudience(String name) {
        return name + "/" + getKdcContext().getKdcRealm() + "@" + getKdcContext().getKdcRealm();
    }

    public KrbMessage getResponse(AuthToken authToken, String passPhrase) {
        KrbMessage krbMessage = null;
        try {
            krbMessage = handleMessage(authToken, passPhrase);
        } catch (KrbException e) {
            LOG.error("Failed to handle message. " + e.getMessage());
        }
        return krbMessage;
    }

    /**
     * Process the client request message.
     */
    public KrbMessage handleMessage(AuthToken authToken, String passPhrase) throws KrbException {

        // set the audiences
        List<String> auds = new ArrayList<String>();
        String audience = getAudience("krbtgt");
        auds.add(audience);
        authToken.setAudiences(auds);

        AsReq asReq = createAsReq(authToken);
        KdcRequest kdcRequest = new AsRequest(asReq, kdcContext);
        kdcRequest.setHttps(true);
        List<EncryptionType> requestedTypes = getEncryptionTypes();
        EncryptionType bestType = EncryptionUtil.getBestEncryptionType(requestedTypes,
                kdcContext.getConfig().getEncryptionTypes());

        if (bestType == null) {
            LOG.error("Can't get the best encryption type.");
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP);
        }

        PrincipalName clientPrincipal = new PrincipalName(authToken.getSubject());
        String clientRealm = asReq.getReqBody().getRealm();
        if (clientRealm == null || clientRealm.isEmpty()) {
            clientRealm = getKdcContext().getKdcRealm();
        }
        clientPrincipal.setRealm(clientRealm);

        // Set the client key
        EncryptionKey clientKey = HasUtil.getClientKey(clientPrincipal.getName(),
            passPhrase, bestType);
        kdcRequest.setClientKey(clientKey);

        // Set the token issuers
        getKdcServer().getKdcConfig().setString(KdcConfigKey.TOKEN_ISSUERS, "has");

        KrbMessage krbResponse;

        try {
            kdcRequest.process();
            krbResponse = kdcRequest.getReply();
        } catch (KrbException e) {
            LOG.error("Error occurred when request tgt. " + e.getMessage());
            if (e instanceof KdcRecoverableException) {
                krbResponse = handleRecoverableException(
                        (KdcRecoverableException) e, kdcRequest);
            } else {
                KrbError krbError = new KrbError();
                krbError.setStime(KerberosTime.now());
                krbError.setSusec(100);
                if (e.getKrbErrorCode() != null) {
                    krbError.setErrorCode(e.getKrbErrorCode());
                } else {
                    krbError.setErrorCode(KrbErrorCode.UNKNOWN_ERR);
                }
                krbError.setCrealm(kdcContext.getKdcRealm());
                if (kdcRequest.getClientPrincipal() != null) {
                    krbError.setCname(kdcRequest.getClientPrincipal());
                }
                krbError.setRealm(kdcContext.getKdcRealm());
                if (kdcRequest.getServerPrincipal() != null) {
                    krbError.setSname(kdcRequest.getServerPrincipal());
                } else {
                    PrincipalName serverPrincipal = kdcRequest.getKdcReq().getReqBody().getSname();
                    serverPrincipal.setRealm(kdcRequest.getKdcReq().getReqBody().getRealm());
                    krbError.setSname(serverPrincipal);
                }
                if (KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY.equals(e.getKrbErrorCode())) {
                    krbError.setEtext("PREAUTH_FAILED");
                } else {
                    krbError.setEtext(e.getMessage());
                }
                krbResponse = krbError;
            }
        }
        return krbResponse;
    }

    /**
     * Process the recoverable exception.
     *
     * @param e The exception return by kdc
     * @param kdcRequest kdc request
     * @return The KrbError
     */
    private KrbMessage handleRecoverableException(KdcRecoverableException e,
                                                  KdcRequest kdcRequest)
            throws KrbException {
        LOG.info("KRB error occurred while processing request:"
                + e.getMessage());

        KrbError error = e.getKrbError();
        error.setStime(KerberosTime.now());
        error.setSusec(100);
        error.setErrorCode(e.getKrbError().getErrorCode());
        error.setRealm(kdcContext.getKdcRealm());
        if (kdcRequest != null) {
            error.setSname(kdcRequest.getKdcReq().getReqBody().getCname());
        } else {
            error.setSname(new PrincipalName("NONE"));
        }
        error.setEtext(e.getMessage());
        return error;
    }

    public AsReq createAsReq(AuthToken authToken) throws KrbException {
        AsReq asReq = new AsReq();
        KdcReqBody body = makeReqBody();
        asReq.setReqBody(body);

        PaTokenRequest tokenPa = new PaTokenRequest();
        KrbToken krbToken = new KrbToken(authToken, TokenFormat.JWT);
        tokenPa.setToken(krbToken);
        TokenInfo info = new TokenInfo();
        info.setTokenVendor(authToken.getIssuer());
        tokenPa.setTokenInfo(info);

        PaDataEntry paDataEntry = new PaDataEntry();
        paDataEntry.setPaDataType(PaDataType.TOKEN_REQUEST);
        paDataEntry.setPaDataValue(KrbCodec.encode(tokenPa));

        PaData paData = new PaData();
        paData.addElement(paDataEntry);
        asReq.setPaData(paData);
        return asReq;
    }

    /**
     * Create the KdcReqBody
     *
     * @return KdcReqBody
     *
     * @throws KrbException e
     */
     protected KdcReqBody makeReqBody() throws KrbException {
        KdcReqBody body = new KdcReqBody();

        long startTime = System.currentTimeMillis();
        body.setFrom(new KerberosTime(startTime));

         // set the client principal as null
        PrincipalName cName = null;
        body.setCname(cName);

        body.setRealm(getKrbContext().getKrbSetting().getKdcRealm());

        PrincipalName sName = getServerPrincipal();
        body.setSname(sName);

        body.setTill(new KerberosTime(startTime + krbContext.getTicketValidTime()));

        int nonce = krbContext.generateNonce();
        body.setNonce(nonce);
//        setChosenNonce(nonce);

        body.setKdcOptions(getKdcOptions());

        HostAddresses addresses = getHostAddresses();
        if (addresses != null) {
            body.setAddresses(addresses);
        }

        body.setEtypes(getEncryptionTypes());

        return body;
    }

    private PrincipalName getServerPrincipal() {
        return KrbUtil.makeTgsPrincipal(getKrbContext().getKrbSetting().getKdcRealm());
    }

    private KdcOptions getKdcOptions() {
        KdcOptions kdcOptions = new KdcOptions();
        // By default enforce these flags
        kdcOptions.setFlag(KdcOption.FORWARDABLE);
        kdcOptions.setFlag(KdcOption.PROXIABLE);
        kdcOptions.setFlag(KdcOption.RENEWABLE_OK);
        return kdcOptions;
    }

    public HostAddresses getHostAddresses() {
        List<HostAddress> hostAddresses = new ArrayList<HostAddress>();
        HostAddresses addresses = null;
        //empty
        if (!hostAddresses.isEmpty()) {
            addresses = new HostAddresses();
            for (HostAddress ha : hostAddresses) {
                addresses.addElement(ha);
            }
        }
        return addresses;
    }

    public List<EncryptionType> getEncryptionTypes() {
        List<EncryptionType> encryptionTypes = krbContext.getConfig().getEncryptionTypes();
        return EncryptionUtil.orderEtypesByStrength(encryptionTypes);
    }
}
