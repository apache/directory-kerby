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

import org.apache.kerby.KOption;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.KrbSetting;
import org.apache.kerby.kerberos.kerb.client.PkinitOption;
import org.apache.kerby.kerberos.kerb.client.TokenOption;
import org.apache.kerby.kerberos.kerb.client.request.AsRequest;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithCert;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithKeytab;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithPasswd;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithToken;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequest;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequestWithTgt;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequestWithToken;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

/**
 * A krb client API for applications to interact with KDC
 */
public abstract class AbstractInternalKrbClient implements InternalKrbClient {
    private KrbContext context;
    private final KrbSetting krbSetting;

    public AbstractInternalKrbClient(KrbSetting krbSetting) {
        this.krbSetting = krbSetting;
    }

    protected KrbContext getContext() {
        return context;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KrbSetting getSetting() {
        return krbSetting;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init() throws KrbException {
        context = new KrbContext();
        context.init(krbSetting);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TgtTicket requestTgt(KOptions requestOptions) throws KrbException {
        AsRequest asRequest = null;

        if (requestOptions.contains(KrbOption.USE_PASSWD)) {
            asRequest = new AsRequestWithPasswd(context);
        } else if (requestOptions.contains(KrbOption.USE_KEYTAB)) {
            asRequest = new AsRequestWithKeytab(context);
        } else if (requestOptions.contains(PkinitOption.USE_ANONYMOUS)) {
            asRequest = new AsRequestWithCert(context);
        } else if (requestOptions.contains(PkinitOption.USE_PKINIT)) {
            asRequest = new AsRequestWithCert(context);
        } else if (requestOptions.contains(TokenOption.USE_TOKEN)) {
            asRequest = new AsRequestWithToken(context);
        } else if (requestOptions.contains(TokenOption.USER_ID_TOKEN)) {
            asRequest = new AsRequestWithToken(context);
        }

        if (asRequest == null) {
            throw new IllegalArgumentException(
                    "No valid krb client request option found");
        }
        if (requestOptions.contains(KrbOption.CLIENT_PRINCIPAL)) {
            String principal = requestOptions.getStringOption(
                    KrbOption.CLIENT_PRINCIPAL);
            principal = fixPrincipal(principal);
            PrincipalName principalName = new PrincipalName(principal);
            if (requestOptions.contains(PkinitOption.USE_ANONYMOUS)) {
                principalName.setNameType(NameType.NT_WELLKNOWN);
            }
            asRequest.setClientPrincipal(principalName);
        }
        if (requestOptions.contains(KrbOption.SERVER_PRINCIPAL)) {
            String serverPrincipalName = requestOptions.getStringOption(KrbOption.SERVER_PRINCIPAL);
            serverPrincipalName = fixPrincipal(serverPrincipalName);
            PrincipalName serverPrincipal = new PrincipalName(serverPrincipalName, NameType.NT_PRINCIPAL);
            asRequest.setServerPrincipal(serverPrincipal);
        }

        asRequest.setRequestOptions(requestOptions);

        return doRequestTgt(asRequest);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SgtTicket requestSgt(KOptions requestOptions) throws KrbException {
        TgsRequest tgsRequest = null;
        if (requestOptions.contains(TokenOption.USER_AC_TOKEN)) {
            tgsRequest = new TgsRequestWithToken(context);
        } else if (requestOptions.contains(KrbOption.USE_TGT)) {
            KOption kOpt = requestOptions.getOption(KrbOption.USE_TGT);
            tgsRequest = new TgsRequestWithTgt(context,
                (TgtTicket) kOpt.getOptionInfo().getValue());
        }

        if (tgsRequest == null) {
            throw new IllegalArgumentException(
                    "No valid krb client request option found");
        }

        String serverPrincipal = fixPrincipal(requestOptions.
                getStringOption(KrbOption.SERVER_PRINCIPAL));
        tgsRequest.setServerPrincipal(new PrincipalName(serverPrincipal));
        tgsRequest.setRequestOptions(requestOptions);

        return doRequestSgt(tgsRequest);
    }

    protected abstract TgtTicket doRequestTgt(
        AsRequest tgtTktReq) throws KrbException;

    protected abstract SgtTicket doRequestSgt(
        TgsRequest tgsRequest) throws KrbException;

    /**
     * Fix principal name.
     *
     * @param principal The principal name
     * @return The fixed principal
     */
    protected String fixPrincipal(String principal) {
        if (!principal.contains("@")) {
            principal += "@" + krbSetting.getKdcRealm();
        }
        return principal;
    }
}
