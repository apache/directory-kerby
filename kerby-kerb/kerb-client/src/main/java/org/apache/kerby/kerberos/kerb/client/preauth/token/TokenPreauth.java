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
package org.apache.kerby.kerberos.kerb.client.preauth.token;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.preauth.AbstractPreauthPlugin;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.preauth.PaFlag;
import org.apache.kerby.kerberos.kerb.preauth.PaFlags;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.token.TokenPreauthMeta;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.spec.base.KrbToken;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.spec.pa.token.PaTokenRequest;
import org.apache.kerby.kerberos.kerb.spec.pa.token.TokenInfo;

import java.util.Collections;
import java.util.List;

public class TokenPreauth extends AbstractPreauthPlugin {

    private TokenContext tokenContext;

    public TokenPreauth() {
        super(new TokenPreauthMeta());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(KrbContext context) {
        super.init(context);
        this.tokenContext = new TokenContext();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
        TokenRequestContext reqCtx = new TokenRequestContext();

        return reqCtx;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void prepareQuestions(KdcRequest kdcRequest,
                                 PluginRequestContext requestContext) {

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<EncryptionType> getEncTypes(KdcRequest kdcRequest,
                                            PluginRequestContext requestContext) {
        return Collections.emptyList();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setPreauthOptions(KdcRequest kdcRequest,
                                  PluginRequestContext requestContext,
                                  KOptions options) {

        tokenContext.usingIdToken = options.getBooleanOption(KrbOption.USE_TOKEN, false);
        if (tokenContext.usingIdToken) {
            if (options.contains(KrbOption.TOKEN_USER_ID_TOKEN)) {
                tokenContext.token =
                        (AuthToken) options.getOptionValue(KrbOption.TOKEN_USER_ID_TOKEN);
            }
        } else {
            if (options.contains(KrbOption.TOKEN_USER_AC_TOKEN)) {
                tokenContext.token =
                        (AuthToken) options.getOptionValue(KrbOption.TOKEN_USER_AC_TOKEN);
            }
        }

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void tryFirst(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {
        if (kdcRequest.getAsKey() == null) {
            kdcRequest.needAsKey();
        }
        outPadata.addElement(makeEntry(kdcRequest));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean process(KdcRequest kdcRequest,
                           PluginRequestContext requestContext,
                           PaDataEntry inPadata,
                           PaData outPadata) throws KrbException {

        if (kdcRequest.getAsKey() == null) {
            kdcRequest.needAsKey();
        }
        outPadata.addElement(makeEntry(kdcRequest));
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean tryAgain(KdcRequest kdcRequest,
                            PluginRequestContext requestContext,
                            PaDataType preauthType,
                            PaData errPadata,
                            PaData outPadata) {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PaFlags getFlags(PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    /**
     * Make padata entry.
     *
     * @param kdcRequest The kdc request
     * @return PaDataEntry to be made.
     */
    private PaDataEntry makeEntry(KdcRequest kdcRequest) throws KrbException {
        KOptions options = kdcRequest.getPreauthOptions();

        KOption idToken = options.getOption(KrbOption.TOKEN_USER_ID_TOKEN);
        KOption acToken = options.getOption(KrbOption.TOKEN_USER_AC_TOKEN);
        AuthToken authToken;
        if (idToken != null) {
            authToken = (AuthToken) idToken.getValue();
        } else if (acToken != null) {
            authToken = (AuthToken) acToken.getValue();
        } else {
            throw new KrbException("missing token.");
        }

        PaTokenRequest tokenPa = new PaTokenRequest();
        tokenPa.setToken((KrbToken) authToken);
        TokenInfo info = new TokenInfo();
        info.setTokenVendor("vendor");
        tokenPa.setTokenInfo(info);

        EncryptedData paDataValue = EncryptionUtil.seal(tokenPa,
                kdcRequest.getAsKey(), KeyUsage.PA_TOKEN);

        PaDataEntry paDataEntry = new PaDataEntry();
        paDataEntry.setPaDataType(PaDataType.TOKEN_REQUEST);
        paDataEntry.setPaDataValue(paDataValue.encode());

        return paDataEntry;
    }
}