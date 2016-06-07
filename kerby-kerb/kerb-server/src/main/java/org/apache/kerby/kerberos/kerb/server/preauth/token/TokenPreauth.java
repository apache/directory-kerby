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
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.common.PrivateKeyReader;
import org.apache.kerby.kerberos.kerb.common.PublicKeyReader;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.token.TokenPreauthMeta;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.server.preauth.AbstractPreauthPlugin;
import org.apache.kerby.kerberos.kerb.server.request.AsRequest;
import org.apache.kerby.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.server.request.TgsRequest;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbToken;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.token.PaTokenRequest;
import org.apache.kerby.kerberos.kerb.type.pa.token.TokenInfo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class TokenPreauth extends AbstractPreauthPlugin {

    public TokenPreauth() {
        super(new TokenPreauthMeta());
    }

    @Override
    public boolean verify(KdcRequest kdcRequest, PluginRequestContext requestContext,
                          PaDataEntry paData) throws KrbException {

        if (!kdcRequest.getKdcContext().getConfig().isAllowTokenPreauth()) {
            throw new KrbException(KrbErrorCode.TOKEN_PREAUTH_NOT_ALLOWED,
                "Token preauth is not allowed.");
        }
        if (paData.getPaDataType() == PaDataType.TOKEN_REQUEST) {
            EncryptedData encData = KrbCodec.decode(paData.getPaDataValue(), EncryptedData.class);
            EncryptionKey clientKey = kdcRequest.getArmorKey();
            kdcRequest.setClientKey(clientKey);

            PaTokenRequest paTokenRequest = EncryptionUtil.unseal(encData, clientKey,
                KeyUsage.PA_TOKEN, PaTokenRequest.class);

            KrbToken token = paTokenRequest.getToken();
            List<String> issuers = kdcRequest.getKdcContext().getConfig().getIssuers();
            TokenInfo tokenInfo = paTokenRequest.getTokenInfo();
            String issuer = tokenInfo.getTokenVendor();
            if (!(issuers.contains(issuer))) {
                throw new KrbException("Unconfigured issuer: " + issuer);
            }
            
            // Configure keys
            TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();
            configureKeys(tokenDecoder, kdcRequest, issuer);
            
            AuthToken authToken = null;
            try {
                authToken = tokenDecoder.decodeFromBytes(token.getTokenValue());
                if (!tokenDecoder.isSigned()) {
                    throw new KrbException("Token should be signed.");
                }
            } catch (IOException e) {
                throw new KrbException("Decoding failed", e);
            }
            
            if (authToken == null) {
                throw new KrbException("Token Decoding failed");
            }

            List<String> audiences = authToken.getAudiences();
            PrincipalName serverPrincipal = kdcRequest.getKdcReq().getReqBody().getSname();
            serverPrincipal.setRealm(kdcRequest.getKdcReq().getReqBody().getRealm());
            kdcRequest.setServerPrincipal(serverPrincipal);
            if (!audiences.contains(serverPrincipal.getName())) {
                throw new KrbException("The token audience does not match with the target server principal!");
            }
            if (kdcRequest instanceof AsRequest) {
                AsRequest asRequest = (AsRequest) kdcRequest;
                asRequest.setToken(authToken);
            } else if (kdcRequest instanceof TgsRequest) {
                TgsRequest tgsRequest = (TgsRequest) kdcRequest;
                tgsRequest.setToken(authToken);
            }
            return true;
        } else {
            return false;
        }
    }

    private void configureKeys(TokenDecoder tokenDecoder, KdcRequest kdcRequest, String issuer) {
        String verifyKeyPath = kdcRequest.getKdcContext().getConfig().getVerifyKeyConfig();
        if (verifyKeyPath != null) {
            File verifyKeyFile = getKeyFile(verifyKeyPath, issuer);
            if (verifyKeyFile != null) {
                PublicKey verifyKey = null;
                try {
                    FileInputStream fis = new FileInputStream(verifyKeyFile);
                    verifyKey = PublicKeyReader.loadPublicKey(fis);
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                tokenDecoder.setVerifyKey(verifyKey);
            }
        }
        String decryptionKeyPath = kdcRequest.getKdcContext().getConfig().getDecryptionKeyConfig();
        if (decryptionKeyPath != null) {
            File decryptionKeyFile = getKeyFile(decryptionKeyPath, issuer);
            if (decryptionKeyFile != null) {
                PrivateKey decryptionKey = null;
                try {
                    FileInputStream fis = new FileInputStream(decryptionKeyFile);
                    decryptionKey = PrivateKeyReader.loadPrivateKey(fis);
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                tokenDecoder.setDecryptionKey(decryptionKey);
            }
        }
    }

    private File getKeyFile(String path, String issuer) {
        File file = new File(path);
        if (file.isDirectory()) {
            File[] listOfFiles = file.listFiles();
            File verifyKeyFile = null;

            if (listOfFiles == null) {
                throw new RuntimeException("List of files is null.");
            }
            for (int i = 0; i < listOfFiles.length; i++) {
                if (listOfFiles[i].isFile() && listOfFiles[i].getName().contains(issuer)) {
                    verifyKeyFile = listOfFiles[i];
                    break;
                }
            }
            return verifyKeyFile;
        } else if (file.isFile()) {
            return file;
        }
        
        return null;
    }
}
