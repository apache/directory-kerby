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
import org.apache.kerby.kerberos.kerb.integration.test.jaas.TokenCache;
import org.apache.kerby.kerberos.kerb.integration.test.jaas.TokenJaasKrbUtil;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.LoginTestBase;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.kerberos.provider.token.JwtTokenProvider;
import org.junit.Before;

import javax.security.auth.Subject;
import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class TokenLoginTestBase extends LoginTestBase {

    private File tokenCache;
    private File armorCache;
    private File tgtCache;

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
    }

    @Override
    protected void configKdcSeverAndClient() {
        super.configKdcSeverAndClient();
        getKdcServer().getKdcConfig().setBoolean(KdcConfigKey.ALLOW_TOKEN_PREAUTH,
                isTokenPreauthAllowed());
    }

    protected Boolean isTokenPreauthAllowed() {
        return true;
    }

    private String createTokenAndArmorCache() throws Exception {

        TokenEncoder tokenEncoder = null;
        try {
            tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        } catch (Exception e) {
            e.printStackTrace();
        }
        AuthToken token = issueToken(getClientPrincipal());
        String tokenStr = tokenEncoder.encodeAsString(token);
        TokenCache.writeToken(tokenStr);
        System.out.println("Issued token: " + tokenStr);
        tokenCache = TokenCache.getDefaultTokenCache();

        TgtTicket tgt = getKrbClient().requestTgtWithPassword(getClientPrincipal(),
                getClientPassword());
        getKrbClient().storeTicket(tgt, armorCache);

        return tokenStr;
    }

    private AuthToken issueToken(String principal) {
        AuthToken authToken = KrbRuntime.getTokenProvider().createTokenFactory().createToken();

        String iss = "token-service";
        authToken.setIssuer(iss);

        String sub = principal;
        authToken.setSubject(sub);

        authToken.addAttribute("group", GROUP);

        authToken.addAttribute("role", ROLE);

        List<String> aud = new ArrayList<String>();
        aud.add("krb5kdc-with-token-extension");
        authToken.setAudiences(aud);

        // Set expiration in 60 minutes
        final Date now = new Date(new Date().getTime() / 1000 * 1000);
        Date exp = new Date(now.getTime() + 1000 * 60 * 60);
        authToken.setExpirationTime(exp);

        Date nbf = now;
        authToken.setNotBeforeTime(nbf);

        Date iat = now;
        authToken.setIssueTime(iat);

        return authToken;
    }

    private Subject loginClientUsingTokenStr(String tokenStr, File armorCache, File tgtCache) throws Exception {
        return TokenJaasKrbUtil.loginUsingToken(getClientPrincipal(), tokenStr, armorCache, tgtCache);
    }

    private Subject loginClientUsingTokenCache(File tokenCache, File armorCache, File tgtCache) throws Exception {
        return TokenJaasKrbUtil.loginUsingToken(getClientPrincipal(), tokenCache, armorCache, tgtCache);
    }

    protected void testLoginWithTokenStr() throws Exception {
        String tokenStr = createTokenAndArmorCache();
        checkSubject(loginClientUsingTokenStr(tokenStr, armorCache, tgtCache));
    }

    protected void testLoginWithTokenCache() throws Exception {
        createTokenAndArmorCache();
        checkSubject(loginClientUsingTokenCache(tokenCache, armorCache, tgtCache));
    }
}
