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
package org.apache.kerby.kerberos.kdc;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.common.PrivateKeyReader;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.KdcTestBase;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.base.KrbToken;
import org.apache.kerby.kerberos.kerb.type.base.TokenFormat;
import org.apache.kerby.kerberos.kerb.type.ticket.KrbTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.kerberos.provider.token.JwtTokenEncoder;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenKdcTestBase extends KdcTestBase {
    static final String SUBJECT = "test-sub";
    static final String ISSUER = "oauth2.com";
    static final String GROUP = "sales-group";
    static final String ROLE = "ADMIN";
    private File cCacheFile;
    private KrbToken krbToken;

    @Override
    protected void configKdcSeverAndClient() {
        super.configKdcSeverAndClient();
        String verifyKeyPath = this.getClass().getResource("/").getPath();
        getKdcServer().getKdcConfig().setString(KdcConfigKey.TOKEN_VERIFY_KEYS, verifyKeyPath);

        URL privateKeyPath = TokenKdcTestBase.class.getResource("/private_key.pem");
        getKdcServer().getKdcConfig().setString(KdcConfigKey.TOKEN_DECRYPTION_KEYS, privateKeyPath.getPath());
        getKdcServer().getKdcConfig().setString(KdcConfigKey.TOKEN_ISSUERS, ISSUER);
    }

    protected KrbToken getKrbToken() {
        return krbToken;
    }

    protected File getcCacheFile() {
        return cCacheFile;
    }

    protected AuthToken prepareToken(String audience) throws Exception {
        InputStream is = TokenKdcTestBase.class.getResourceAsStream("/private_key.pem");
        PrivateKey privateKey = PrivateKeyReader.loadPrivateKey(is);

        return prepareToken(audience, ISSUER, privateKey, null);
    }

    protected AuthToken prepareToken(String audience, String issuer,
                                     PrivateKey signingKey, PublicKey encryptionKey) {
        AuthToken authToken = KrbRuntime.getTokenProvider("JWT").createTokenFactory().createToken();
        authToken.setIssuer(issuer);
        authToken.setSubject(SUBJECT);

        authToken.addAttribute("group", GROUP);
        authToken.addAttribute("role", ROLE);

        List<String> aud = new ArrayList<String>();
        aud.add(audience);
        authToken.setAudiences(aud);

        // Set expiration in 60 minutes
        final Date now = new Date();
        Date exp = new Date(now.getTime() + 1000 * 60 * 60);
        authToken.setExpirationTime(exp);

        Date nbf = now;
        authToken.setNotBeforeTime(nbf);

        Date iat = now;
        authToken.setIssueTime(iat);

        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();

        if (tokenEncoder instanceof JwtTokenEncoder && signingKey != null) {
            tokenEncoder.setSignKey(signingKey);
        }
        if (tokenEncoder instanceof JwtTokenEncoder && encryptionKey != null) {
            tokenEncoder.setEncryptionKey(encryptionKey);
        }

        krbToken = new KrbToken();
        krbToken.setInnerToken(authToken);
        krbToken.setTokenType();
        krbToken.setTokenFormat(TokenFormat.JWT);
        try {
            krbToken.setTokenValue(tokenEncoder.encodeAsBytes(authToken));
        } catch (KrbException e) {
            throw new RuntimeException("Failed to encode AuthToken", e);
        }

        return krbToken;
    }


    protected File createCredentialCache(String principal,
                                       String password) throws Exception {
        TgtTicket tgt = getKrbClient().requestTgt(principal, password);
        writeTgtToCache(tgt, principal);
        return cCacheFile;
    }

    /**
     * Write tgt into credentials cache.
     */
    private void writeTgtToCache(
            TgtTicket tgt, String principal) throws IOException {
        Credential credential = new Credential(tgt);
        CredentialCache cCache = new CredentialCache();
        cCache.addCredential(credential);
        cCache.setPrimaryPrincipal(tgt.getClientPrincipal());

        String fileName = "krb5_" + principal + ".cc";
        cCacheFile = new File(getTestDir().getPath(), fileName);
        cCache.store(cCacheFile);
    }

    protected void deleteCcacheFile() {
        cCacheFile.delete();
    }

    protected void verifyTicket(KrbTicket ticket) {
        assertThat(ticket).isNotNull();
        assertThat(ticket.getRealm()).isEqualTo(getKdcServer().getKdcSetting().getKdcRealm());
        assertThat(ticket.getTicket()).isNotNull();
        assertThat(ticket.getSessionKey()).isNotNull();
        assertThat(ticket.getEncKdcRepPart()).isNotNull();
    }
}
