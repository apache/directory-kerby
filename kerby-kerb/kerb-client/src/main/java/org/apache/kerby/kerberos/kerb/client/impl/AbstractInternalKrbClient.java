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
import org.apache.kerby.kerberos.kerb.client.request.AsRequest;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithCert;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithKeytab;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithPasswd;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithToken;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequest;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequestWithTgt;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequestWithToken;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;

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
        } else if (requestOptions.contains(KrbOption.TOKEN_USER_ID_TOKEN)) {
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

    /**
     * {@inheritDoc}
     */
    @Override
    public ServiceTicket requestServiceTicket(KOptions requestOptions) throws KrbException {
        TgsRequest tgsRequest = null;
        if (requestOptions.contains(KrbOption.TOKEN_USER_AC_TOKEN)) {
            tgsRequest = new TgsRequestWithToken(context);
        } else if (requestOptions.contains(KrbOption.USE_TGT)) {
            KOption tgt = requestOptions.getOption(KrbOption.USE_TGT);
            tgsRequest = new TgsRequestWithTgt(context, (TgtTicket) tgt.getValue());
        }

        if (tgsRequest == null) {
            throw new IllegalArgumentException(
                    "No valid krb client request option found");
        }
        tgsRequest.setServerPrincipal(new PrincipalName(requestOptions.
                getStringOption(KrbOption.SERVER_PRINCIPAL)));
        tgsRequest.setKrbOptions(requestOptions);

        return doRequestServiceTicket(tgsRequest);
    }

    protected abstract TgtTicket doRequestTgtTicket(
            AsRequest tgtTktReq) throws KrbException;

    protected abstract ServiceTicket doRequestServiceTicket(
            TgsRequest tgsRequest) throws KrbException;
}
