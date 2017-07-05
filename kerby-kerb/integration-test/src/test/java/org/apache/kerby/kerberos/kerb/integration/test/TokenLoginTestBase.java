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
package org.apache.kerby.kerberos.kerb.integration.test;

import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.client.jaas.TokenCache;
import org.apache.kerby.kerberos.kerb.client.jaas.TokenJaasKrbUtil;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.LoginTestBase;
import org.apache.kerby.kerberos.kerb.server.TestKdcServer;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.kerberos.provider.token.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.junit.After;
import org.junit.Before;

import javax.security.auth.Subject;
import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class TokenLoginTestBase extends LoginTestBase {
    private static final Logger LOG = LoggerFactory
            .getLogger(TokenLoginTestBase.class);
    private File tokenCache;
    private File armorCache;
    private File tgtCache;
    private File signKeyFile;

    static final String GROUP = "sales-group";
    static final String ROLE = "ADMIN";

    static {
        KrbRuntime.setTokenProvider(new JwtTokenProvider());
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        armorCache = new File(getTestDir(), "armorcache.cc");
        tgtCache = new File(getTestDir(), "tgtcache.cc");
        signKeyFile = new File(this.getClass().getResource("/private_key.pem").getPath());
        tokenCache = File.createTempFile("tokencache", null);
    }

    @After
    public void cleanup() throws Exception {
        tokenCache.delete();
    }

    @Override
    protected void configKdcSeverAndClient() {
        super.configKdcSeverAndClient();
        getKdcServer().getKdcConfig().setBoolean(KdcConfigKey.ALLOW_TOKEN_PREAUTH,
            isTokenPreauthAllowed());
        String verifyKeyFile = this.getClass().getResource("/").getPath();
        getKdcServer().getKdcConfig().setString(KdcConfigKey.TOKEN_VERIFY_KEYS, verifyKeyFile);
        getKdcServer().getKdcConfig().setString(KdcConfigKey.TOKEN_ISSUERS, "token-service");
    }

    protected Boolean isTokenPreauthAllowed() {
        return true;
    }

    protected String createTokenAndArmorCache() throws Exception {

        TokenEncoder tokenEncoder = null;
        try {
            tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        } catch (Exception e) {
            LOG.error("Failed to create token. " + e.toString());
        }
        AuthToken token = issueToken(getClientPrincipal());
        String tokenStr = tokenEncoder.encodeAsString(token);

        TokenCache.writeToken(tokenStr, tokenCache.getPath());
        // System.out.println("Issued token: " + tokenStr);

        TgtTicket tgt = getKrbClient().requestTgt(getClientPrincipal(),
            getClientPassword());
        getKrbClient().storeTicket(tgt, armorCache);

        return tokenStr;
    }

    protected AuthToken issueToken(String principal) {
        AuthToken authToken = KrbRuntime.getTokenProvider().createTokenFactory().createToken();

        String iss = "token-service";
        authToken.setIssuer(iss);

        String sub = principal;
        authToken.setSubject(sub);

        authToken.addAttribute("group", GROUP);

        authToken.addAttribute("role", ROLE);

        List<String> aud = new ArrayList<String>();
        aud.add(KrbUtil.makeTgsPrincipal(TestKdcServer.KDC_REALM).getName());
        authToken.setAudiences(aud);

        // Set expiration in 60 minutes
        final Date now = new Date();
        Date exp = new Date(now.getTime() + 1000 * 60 * 60);
        authToken.setExpirationTime(exp);

        Date nbf = now;
        authToken.setNotBeforeTime(nbf);

        Date iat = now;
        authToken.setIssueTime(iat);

        return authToken;
    }

    protected Subject loginClientUsingTokenStr(String tokenStr, File armorCache, File tgtCache,
                                             File signKeyFile) throws Exception {
        return TokenJaasKrbUtil.loginUsingToken(getClientPrincipal(), tokenStr, armorCache,
            tgtCache, signKeyFile);
    }

    private Subject loginClientUsingTokenCache(File tokenCache, File armorCache, File tgtCache,
                                               File signKeyFile) throws Exception {
        return TokenJaasKrbUtil.loginUsingToken(getClientPrincipal(), tokenCache, armorCache,
            tgtCache, signKeyFile);
    }

    protected void testLoginWithTokenStr() throws Exception {
        String tokenStr = createTokenAndArmorCache();
        Subject subj = loginClientUsingTokenStr(tokenStr, armorCache, tgtCache, signKeyFile);
        checkSubject(subj);
    }

    protected void testLoginWithTokenCache() throws Exception {
        createTokenAndArmorCache();
        checkSubject(loginClientUsingTokenCache(tokenCache, armorCache, tgtCache, signKeyFile));
    }

    protected Subject testLoginWithTokenCacheAndRetSubject() throws Exception {
        createTokenAndArmorCache();
        Subject subj = loginClientUsingTokenCache(tokenCache, armorCache, tgtCache, signKeyFile);
        checkSubject(subj);
        return subj;
    }

    protected File getArmorCache() {
        return armorCache;
    }

    protected File getTGTCache() {
        return tgtCache;
    }

    protected File getSignKeyFile() {
        return signKeyFile;
    }
}
