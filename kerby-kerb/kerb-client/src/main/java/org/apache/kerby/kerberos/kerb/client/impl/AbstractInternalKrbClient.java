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
package org.apache.kerby.kerberos.kerb.client.impl;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.*;
import org.apache.kerby.kerberos.kerb.client.request.*;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;

import java.io.File;
import java.io.IOException;

/**
 * A krb client API for applications to interact with KDC
 */
public abstract class AbstractInternalKrbClient implements InternalKrbClient {
    private KrbContext context;
    private KrbConfig krbConfig;
    private KrbSetting krbSetting;

    protected KrbContext getContext() {
        return context;
    }

    @Override
    public KrbSetting getSetting() {
        return krbSetting;
    }

    @Override
    public void init(KOptions commonOptions) throws KrbException {

        try {
            initConfig(commonOptions);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load config", e);
        }

        krbSetting = new KrbSetting(commonOptions, krbConfig);
        context = new KrbContext();
        context.init(krbConfig);
    }

    /**
     * Prepare krb config, loading krb5.conf if necessary.
     */
    private void initConfig(KOptions commonOptions) throws IOException {
        krbConfig = (KrbConfig) commonOptions.getOptionValue(KrbOption.KRB_CONFIG);
        if (krbConfig == null) {
            krbConfig = new KrbConfig();

            File confDir = commonOptions.getDirOption(KrbOption.CONF_DIR);
            if (confDir == null) {
                confDir = new File("/etc/"); // for Linux. TODO: fix for Win etc.
            }
            if (confDir != null && confDir.exists()) {
                File kdcConfFile = new File(confDir, "krb5.conf");
                if (kdcConfFile.exists()) {
                    krbConfig.addIniConfig(kdcConfFile);
                }
            }
        }
    }

    @Override
    public TgtTicket requestTgtTicket(KOptions requestOptions) throws KrbException {
        AsRequest asRequest = null;

        if (requestOptions.contains(KrbOption.USE_PASSWD)) {
            asRequest = new AsRequestWithPasswd(context);
        } else if (requestOptions.contains(KrbOption.USE_KEYTAB)) {
            asRequest = new AsRequestWithKeytab(context);
        } else if (requestOptions.contains(KrbOption.USE_PKINIT_ANONYMOUS)) {
            asRequest = new AsRequestWithCert(context);
        } else if (requestOptions.contains(KrbOption.USE_PKINIT)) {
            asRequest = new AsRequestWithCert(context);
        } else if (requestOptions.contains(KrbOption.USE_TOKEN)) {
            asRequest = new AsRequestWithToken(context);
        }

        if (asRequest == null) {
            throw new IllegalArgumentException(
                    "No valid krb client request option found");
        }
        if (requestOptions.contains(KrbOption.CLIENT_PRINCIPAL)) {
            String principal = requestOptions.getStringOption(
                    KrbOption.CLIENT_PRINCIPAL);
            asRequest.setClientPrincipal(new PrincipalName(principal));
        }
        asRequest.setKrbOptions(requestOptions);

        return doRequestTgtTicket(asRequest);
    }

    @Override
    public ServiceTicket requestServiceTicketWithTgt(
            TgtTicket tgt, String serverPrincipal) throws KrbException {

        TgsRequest ticketReq = new TgsRequest(context, tgt);
        ticketReq.setServerPrincipal(new PrincipalName(serverPrincipal));
        return doRequestServiceTicket(ticketReq);
    }

    @Override
    public ServiceTicket requestServiceTicketWithAccessToken(
            AuthToken token, String serverPrincipal) throws KrbException {
        TgsRequest tgsRequest = new TgsRequestWithToken(context);
        return doRequestServiceTicket(tgsRequest);
    }

    protected abstract TgtTicket doRequestTgtTicket(
            AsRequest tgtTktReq) throws KrbException;

    protected abstract ServiceTicket doRequestServiceTicket(
            TgsRequest tgsRequest) throws KrbException;
}
