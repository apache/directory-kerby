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
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.client.impl.DefaultInternalKrbClient;
import org.apache.kerby.kerberos.kerb.client.impl.InternalKrbClient;
import org.apache.kerby.kerberos.kerb.type.kdc.EncAsRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

/**
 * A Krb client API for applications to interact with KDC
 */
public class KrbClientBase {
    private final KrbConfig krbConfig;
    private final KOptions commonOptions;
    private final KrbSetting krbSetting;

    private InternalKrbClient innerClient;
    private static final Logger LOG = LoggerFactory.getLogger(KrbClientBase.class);

    /**
     * Default constructor.
     * @throws KrbException e
     */
    public KrbClientBase() throws KrbException {
        this.krbConfig = ClientUtil.getDefaultConfig();
        this.commonOptions = new KOptions();
        this.krbSetting = new KrbSetting(commonOptions, krbConfig);
    }

    /**
     * Construct with prepared KrbConfig.
     * @param krbConfig The krb config
     */
    public KrbClientBase(KrbConfig krbConfig) {
        this.krbConfig = krbConfig;
        this.commonOptions = new KOptions();
        this.krbSetting = new KrbSetting(commonOptions, krbConfig);
    }

    /**
     * Constructor with conf dir
     * @param confDir The conf dir
     * @throws KrbException e
     */
    public KrbClientBase(File confDir) throws KrbException {
        this.commonOptions = new KOptions();
        this.krbConfig = ClientUtil.getConfig(confDir);
        this.krbSetting = new KrbSetting(commonOptions, krbConfig);
    }

    /**
     * Constructor with prepared KrbClientBase.
     * @param krbClient The krb client
     */
    public KrbClientBase(KrbClientBase krbClient) {
        this.commonOptions = krbClient.commonOptions;
        this.krbConfig = krbClient.krbConfig;
        this.krbSetting = krbClient.krbSetting;
        this.innerClient = krbClient.innerClient;
    }


    /**
     * Set KDC realm for ticket request
     * @param realm The realm
     */
    public void setKdcRealm(String realm) {
        commonOptions.add(KrbOption.KDC_REALM, realm);
    }

    /**
     * Set KDC host.
     * @param kdcHost The kdc host
     */
    public void setKdcHost(String kdcHost) {
        commonOptions.add(KrbOption.KDC_HOST, kdcHost);
    }

    /**
     * Set KDC tcp port.
     * @param kdcTcpPort The kdc tcp port
     */
    public void setKdcTcpPort(int kdcTcpPort) {
        if (kdcTcpPort < 1) {
            throw new IllegalArgumentException("Invalid port");
        }
        commonOptions.add(KrbOption.KDC_TCP_PORT, kdcTcpPort);
        setAllowTcp(true);
    }

    /**
     * Set to allow UDP or not.
     * @param allowUdp true if allow udp
     */
    public void setAllowUdp(boolean allowUdp) {
        commonOptions.add(KrbOption.ALLOW_UDP, allowUdp);
    }

    /**
     * Set to allow TCP or not.
     * @param allowTcp true if allow tcp
     */
    public void setAllowTcp(boolean allowTcp) {
        commonOptions.add(KrbOption.ALLOW_TCP, allowTcp);
    }

    /**
     * Set KDC udp port. Only makes sense when allowUdp is set.
     * @param kdcUdpPort The kdc udp port
     */
    public void setKdcUdpPort(int kdcUdpPort) {
        if (kdcUdpPort < 1) {
            throw new IllegalArgumentException("Invalid port");
        }
        commonOptions.add(KrbOption.KDC_UDP_PORT, kdcUdpPort);
        setAllowUdp(true);
    }

    /**
     * Set time out for connection
     * @param timeout in seconds
     */
    public void setTimeout(int timeout) {
        commonOptions.add(KrbOption.CONN_TIMEOUT, timeout);
    }

    /**
     * Init the client.
     * @throws KrbException e
     */
    public void init() throws KrbException {
        innerClient = new DefaultInternalKrbClient(krbSetting);
        innerClient.init();
    }

    /**
     * Get krb client settings from options and configs.
     * @return setting
     */
    public KrbSetting getSetting() {
        return krbSetting;
    }

    public KrbConfig getKrbConfig() {
        return krbConfig;
    }

    /**
     * Request a TGT with using well prepared requestOptions.
     * @param requestOptions The request options
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt(KOptions requestOptions) throws KrbException {
        if (requestOptions == null) {
            throw new IllegalArgumentException("Null requestOptions specified");
        }

        return innerClient.requestTgt(requestOptions);
    }

    /**
     * Request a service ticket with a TGT targeting for a server
     * @param tgt The tgt ticket
     * @param serverPrincipal The server principal
     * @return Service ticket
     * @throws KrbException e
     */
    public SgtTicket requestSgt(TgtTicket tgt,
                                String serverPrincipal) throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.USE_TGT, tgt);
        requestOptions.add(KrbOption.SERVER_PRINCIPAL, serverPrincipal);
        return innerClient.requestSgt(requestOptions);
    }

    /**
     * Request a service ticket provided request options
     * @param requestOptions The request options
     * @return service ticket
     * @throws KrbException e
     */
    public SgtTicket requestSgt(KOptions requestOptions) throws KrbException {
        return innerClient.requestSgt(requestOptions);
    }

    /**
     * Request a service ticket
     * @param ccFile The credential cache file
     * @return service ticket
     * @throws KrbException e
     */
    public SgtTicket requestSgt(File ccFile) throws KrbException {
        Credential credential = getCredentialFromFile(ccFile);
        String servicePrincipal = credential.getServicePrincipal().getName();
        TgtTicket tgt = getTgtTicketFromCredential(credential);

        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbKdcOption.RENEW);
        requestOptions.add(KrbOption.USE_TGT, tgt);
        requestOptions.add(KrbOption.SERVER_PRINCIPAL, servicePrincipal);
        SgtTicket sgtTicket = innerClient.requestSgt(requestOptions);
        sgtTicket.setClientPrincipal(tgt.getClientPrincipal());
        return sgtTicket;
    }


    /**
     * Store tgt into the specified credential cache file.
     * @param tgtTicket The tgt ticket
     * @param ccacheFile The credential cache file
     * @throws KrbException e
     */
    public void storeTicket(TgtTicket tgtTicket,
                            File ccacheFile) throws KrbException {
        LOG.info("Storing the tgt to the credential cache file.");
        if (!ccacheFile.exists()) {
            try {
                if (!ccacheFile.createNewFile()) {
                    throw new KrbException("Failed to create ccache file "
                        + ccacheFile.getAbsolutePath());
                }
                // sets read-write permissions to owner only
                ccacheFile.setReadable(false, false);
                ccacheFile.setReadable(true, true);
                if (!ccacheFile.setWritable(true, true)) {
                    throw new KrbException("Cache file is not readable.");
                }
            } catch (IOException e) {
                throw new KrbException("Failed to create ccache file "
                    + ccacheFile.getAbsolutePath(), e);
            }
        }
        if (ccacheFile.exists() && ccacheFile.canWrite()) {
            CredentialCache cCache = new CredentialCache(tgtTicket);
            try {
                cCache.store(ccacheFile);
            } catch (IOException e) {
                throw new KrbException("Failed to store tgt", e);
            }
        } else {
            throw new IllegalArgumentException("Invalid ccache file, "
                    + "not exist or writable: " + ccacheFile.getAbsolutePath());
        }
    }

    /**
     * Store sgt into the specified credential cache file.
     * @param sgtTicket The sgt ticket
     * @param ccacheFile The credential cache file
     * @throws KrbException e
     */
    public void storeTicket(SgtTicket sgtTicket, File ccacheFile) throws KrbException {
        LOG.info("Storing the sgt to the credential cache file.");
        if (!ccacheFile.exists()) {
            try {
                if (!ccacheFile.createNewFile()) {
                    throw new KrbException("Failed to create ccache file "
                        + ccacheFile.getAbsolutePath());
                }
                // sets read-write permissions to owner only
                ccacheFile.setReadable(false, false);
                ccacheFile.setReadable(true, true);
                if (!ccacheFile.setWritable(true, true)) {
                    throw new KrbException("Cache file is not readable.");
                }
            } catch (IOException e) {
                throw new KrbException("Failed to create ccache file "
                    + ccacheFile.getAbsolutePath(), e);
            }
        }
        if (ccacheFile.exists() && ccacheFile.canWrite()) {
            CredentialCache cCache = new CredentialCache(sgtTicket);
            try {
                cCache.store(ccacheFile);
            } catch (IOException e) {
                throw new KrbException("Failed to store tgt", e);
            }
        } else {
            throw new IllegalArgumentException("Invalid ccache file, "
                    + "not exist or writable: " + ccacheFile.getAbsolutePath());
        }
    }

    public TgtTicket getTgtTicketFromCredential(Credential cc) {
        EncAsRepPart encAsRepPart = new EncAsRepPart();
        encAsRepPart.setAuthTime(cc.getAuthTime());
        encAsRepPart.setCaddr(cc.getClientAddresses());
        encAsRepPart.setEndTime(cc.getEndTime());
        encAsRepPart.setFlags(cc.getTicketFlags());
        encAsRepPart.setKey(cc.getKey());
//        encAsRepPart.setKeyExpiration();
//        encAsRepPart.setLastReq();
//        encAsRepPart.setNonce();
        encAsRepPart.setRenewTill(cc.getRenewTill());
        encAsRepPart.setSname(cc.getServerName());
        encAsRepPart.setSrealm(cc.getServerName().getRealm());
        encAsRepPart.setStartTime(cc.getStartTime());
        TgtTicket tgtTicket = new TgtTicket(cc.getTicket(), encAsRepPart, cc.getClientName());
        return tgtTicket;
    }

    public Credential getCredentialFromFile(File ccFile) throws KrbException {
        CredentialCache cc;
        try {
            cc = resolveCredCache(ccFile);
        } catch (IOException e) {
            throw new KrbException("Failed to load armor cache file");
        }
        return cc.getCredentials().iterator().next();
    }

    public CredentialCache resolveCredCache(File ccacheFile) throws IOException {
        CredentialCache cc = new CredentialCache();
        cc.load(ccacheFile);

        return cc;
    }
}
