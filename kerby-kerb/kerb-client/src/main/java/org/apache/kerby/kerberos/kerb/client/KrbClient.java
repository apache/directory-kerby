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
package org.apache.kerby.kerberos.kerb.client;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.impl.DefaultInternalKrbClient;
import org.apache.kerby.kerberos.kerb.client.impl.event.EventBasedKrbClient;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * A Krb client API for applications to interact with KDC
 */
public class KrbClient {

    private KOptions commonOptions;
    private InternalKrbClient innerClient;

    /**
     * Default constructor.
     */
    public KrbClient() {
        commonOptions = new KOptions();
    }

    /**
     * Construct with prepared KrbConfig.
     * @param krbConfig
     */
    public KrbClient(KrbConfig krbConfig) {
        commonOptions = new KOptions();
        commonOptions.add(KrbOption.KRB_CONFIG, krbConfig);
    }

    /**
     * Set the conf dir
     * @param file
     */
    public void setConfDir(File file) throws IOException {
        commonOptions.add(KrbOption.CONF_DIR, file);
    }

    /**
     * Set KDC realm for ticket request
     * @param realm
     */
    public void setKdcRealm(String realm) {
        commonOptions.add(KrbOption.KDC_REALM, realm);
    }

    /**
     * Set KDC host.
     * @param kdcHost
     */
    public void setKdcHost(String kdcHost) {
        commonOptions.add(KrbOption.KDC_HOST, kdcHost);
    }

    /**
     * Set KDC tcp port.
     * @param kdcTcpPort
     */
    public void setKdcTcpPort(int kdcTcpPort) {
        commonOptions.add(KrbOption.KDC_TCP_PORT, kdcTcpPort);
    }

    /**
     * Set to allow UDP or not.
     * @param allowUdp
     */
    public void setAllowUdp(boolean allowUdp) {
        commonOptions.add(KrbOption.ALLOW_UDP, allowUdp);
    }

    /**
     * Set to allow TCP or not.
     * @param allowTcp
     */
    public void setAllowTcp(boolean allowTcp) {
        commonOptions.add(KrbOption.ALLOW_TCP, allowTcp);
    }
    /**
     * Set KDC udp port. Only makes sense when allowUdp is set.
     * @param kdcUdpPort
     */
    public void setKdcUdpPort(int kdcUdpPort) {
        commonOptions.add(KrbOption.KDC_UDP_PORT, kdcUdpPort);
    }

    /**
     * Set time out for connection
     * @param timeout in seconds
     */
    public void setTimeout(int timeout) {
        commonOptions.add(KrbOption.CONN_TIMEOUT, timeout);
    }

    /**
     * Use event model. By default blocking model is used.
     */
    public void useEventModel() {
        commonOptions.add(KrbOption.USE_EVENT_MODEL);
    }

    /**
     * Init the client.
     * @throws KrbException
     */
    public void init() throws KrbException {
        if (commonOptions.contains(KrbOption.USE_EVENT_MODEL)) {
            innerClient = new EventBasedKrbClient();
        } else {
            innerClient = new DefaultInternalKrbClient();
        }
        innerClient.init(commonOptions);
    }

    /**
     * Get krb client settings from options and configs.
     * Note it must be called after init().
     * @return setting
     */
    public KrbSetting getSetting() {
        if (innerClient == null) {
            throw new RuntimeException("Not init yet");
        }
        return innerClient.getSetting();
    }

    /**
     * Request a TGT with user plain credential
     * @param principal
     * @param password
     * @return
     * @throws KrbException
     */
    public TgtTicket requestTgtWithPassword(String principal,
                                      String password) throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.CLIENT_PRINCIPAL, principal);
        requestOptions.add(KrbOption.USE_PASSWD, true);
        requestOptions.add(KrbOption.USER_PASSWD, password);
        return requestTgtWithOptions(requestOptions);
    }

    /**
     * Request a TGT with user plain credential
     * @param principal
     * @param keytabFile
     * @return TGT
     * @throws KrbException
     */
    public TgtTicket requestTgtWithKeytab(String principal,
                                      String keytabFile) throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.CLIENT_PRINCIPAL, principal);
        requestOptions.add(KrbOption.USE_KEYTAB, true);
        requestOptions.add(KrbOption.KEYTAB_FILE, keytabFile);
        return requestTgtWithOptions(requestOptions);
    }

    /**
     * Request a TGT with user x509 certificate credential
     * @param principal
     * @param certificate
     * @param privateKey
     * @return TGT
     * @throws KrbException
     */
    public TgtTicket requestTgtWithCert(String principal, Certificate certificate,
                                        PrivateKey privateKey) throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.PKINIT_X509_CERTIFICATE, certificate);
        requestOptions.add(KrbOption.PKINIT_X509_PRIVATE_KEY, privateKey);
        return requestTgtWithOptions(requestOptions);
    }

    /**
     * Request a TGT with using Anonymous PKINIT
     * @return TGT
     * @throws KrbException
     */
    public TgtTicket requestTgtWithPkintAnonymous() throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.USE_PKINIT_ANONYMOUS);
        return requestTgtWithOptions(requestOptions);
    }

    /**
     * Request a TGT with user token credential
     * @param token
     * @return TGT
     * @throws KrbException
     */
    public TgtTicket requestTgtWithToken(AuthToken token, String armorCache) throws KrbException {
        if (! token.isIdToken()) {
            throw new IllegalArgumentException("Identity token is expected");
        }

        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.TOKEN_USER_ID_TOKEN, token);
        requestOptions.add(KrbOption.ARMOR_CACHE, armorCache);
        return requestTgtWithOptions(requestOptions);
    }

    /**
     * Request a TGT with using well prepared requestOptions.
     * @param requestOptions
     * @return TGT
     * @throws KrbException
     */
    public TgtTicket requestTgtWithOptions(KOptions requestOptions) throws KrbException {
        if (requestOptions == null) {
            throw new IllegalArgumentException("Null KrbOptions specified");
        }

        return innerClient.requestTgtTicket(requestOptions);
    }

    /**
     * Request a service ticket with a TGT targeting for a server
     * @param tgt
     * @param serverPrincipal
     * @return
     * @throws KrbException
     */
    public ServiceTicket requestServiceTicketWithTgt(
            TgtTicket tgt, String serverPrincipal) throws KrbException {
        return innerClient.requestServiceTicketWithTgt(tgt, serverPrincipal);
    }

    /**
     * Request a service ticket using an Access Token.
     * @return service ticket
     * @throws KrbException
     */
    public ServiceTicket requestServiceTicketWithAccessToken(
            AuthToken token, String serverPrincipal) throws KrbException {
        if (! token.isAcToken()) {
            throw new IllegalArgumentException("Access token is expected");
        }
        return innerClient.requestServiceTicketWithAccessToken(token, serverPrincipal);
    }
}
