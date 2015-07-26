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
package org.apache.kerby.kerberos.kerb.server.preauth.token;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.token.TokenPreauthMeta;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.server.preauth.AbstractPreauthPlugin;
import org.apache.kerby.kerberos.kerb.server.request.AsRequest;
import org.apache.kerby.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.server.request.TgsRequest;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.spec.base.KrbToken;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.spec.pa.token.PaTokenRequest;

import java.io.IOException;
import java.util.List;

public class TokenPreauth extends AbstractPreauthPlugin {

    public TokenPreauth() {
        super(new TokenPreauthMeta());
    }

    @Override
    public boolean verify(KdcRequest kdcRequest, PluginRequestContext requestContext,
                          PaDataEntry paData) throws KrbException {

        if (!kdcRequest.getKdcContext().getConfig().isAllowTokenPreauth()) {
            throw new KrbException("Token preauth is not allowed.");
        }
        if (paData.getPaDataType() == PaDataType.TOKEN_REQUEST) {
            EncryptedData encData = KrbCodec.decode(paData.getPaDataValue(), EncryptedData.class);
            EncryptionKey clientKey = kdcRequest.getArmorKey();
            kdcRequest.setClientKey(clientKey);

            PaTokenRequest paTokenRequest = EncryptionUtil.unseal(encData, clientKey,
                KeyUsage.PA_TOKEN, PaTokenRequest.class);

            KrbToken token = paTokenRequest.getToken();

            TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();
            AuthToken authToken = null;
            try {
                authToken = tokenDecoder.decodeFromBytes(token.getTokenValue());
            } catch (IOException e) {
                throw new KrbException("Decoding failed", e);
            }

            if (kdcRequest instanceof AsRequest) {
                AsRequest asRequest = (AsRequest) kdcRequest;
                asRequest.setToken(authToken);
            } else if (kdcRequest instanceof TgsRequest) {
                TgsRequest tgsRequest = (TgsRequest) kdcRequest;
                tgsRequest.setToken(authToken);
                List<String> audiences = authToken.getAudiences();
                PrincipalName serverPrincipal = kdcRequest.getKdcReq().getReqBody().getSname();
                serverPrincipal.setRealm(kdcRequest.getKdcReq().getReqBody().getRealm());
                kdcRequest.setServerPrincipal(serverPrincipal);
                if (!audiences.contains(serverPrincipal.getName())) {
                    throw new KrbException("Token audience not match with the target server principal!");
                }
            }

            return true;
        } else {
            return false;
        }
    }
}
