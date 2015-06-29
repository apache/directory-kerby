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
import org.apache.kerby.kerberos.kerb.server.KdcTestBase;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.base.KrbToken;
import org.apache.kerby.kerberos.kerb.spec.base.TokenFormat;
import org.apache.kerby.kerberos.kerb.spec.ticket.AbstractServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.kerberos.provider.token.JwtTokenProvider;
import org.junit.Before;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class WithTokenKdcTestBase extends KdcTestBase {
    static final String SUBJECT = "test-sub";
    static final String AUDIENCE = "krbtgt@EXAMPLE.COM";
    static final String ISSUER = "oauth2.com";
    static final String GROUP = "sales-group";
    static final String ROLE = "ADMIN";
    private File cCacheFile;
    private AuthToken krbToken;

    @Before
    public void setUp() throws Exception {
        KrbRuntime.setTokenProvider(new JwtTokenProvider());
        super.setUp();
    }

    @Override
    protected void createPrincipals() throws KrbException {
        super.createPrincipals();
        kdcServer.createPrincipal(getClientPrincipal(), clientPassword);
    }

    @Override
    protected void deletePrincipals() throws KrbException {
        super.deletePrincipals();
        kdcServer.deletePrincipal(getClientPrincipal());
    }

    protected AuthToken getKrbToken() {
        return krbToken;
    }

    protected File getcCacheFile() {
        return cCacheFile;
    }

    protected AuthToken prepareToken(String servicePrincipal) {
        AuthToken authToken = KrbRuntime.getTokenProvider().createTokenFactory().createToken();
        authToken.setIssuer(ISSUER);
        authToken.setSubject(SUBJECT);

        authToken.addAttribute("group", GROUP);
        authToken.addAttribute("role", ROLE);

        List<String> aud = new ArrayList<String>();
        if(servicePrincipal != null) {
            aud.add(servicePrincipal);
        }
        aud.add(AUDIENCE);
        authToken.setAudiences(aud);

        // Set expiration in 60 minutes
        final Date NOW =  new Date(new Date().getTime() / 1000 * 1000);
        Date exp = new Date(NOW.getTime() + 1000 * 60 * 60);
        authToken.setExpirationTime(exp);

        Date nbf = NOW;
        authToken.setNotBeforeTime(nbf);

        Date iat = NOW;
        authToken.setIssueTime(iat);
        krbToken = new KrbToken(authToken, TokenFormat.JWT);
        return krbToken;
    }

    @Override
    protected void prepareKdcServer() throws Exception {
        super.prepareKdcServer();
    }

    protected File createCredentialCache(String principal,
                                       String password) throws Exception {
        TgtTicket tgt = krbClnt.requestTgtWithPassword(principal, password);
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

    protected void verifyTicket(AbstractServiceTicket ticket) {
        assertThat(ticket).isNotNull();
        assertThat(ticket.getRealm()).isEqualTo(kdcServer.getKdcRealm());
        assertThat(ticket.getTicket()).isNotNull();
        assertThat(ticket.getSessionKey()).isNotNull();
        assertThat(ticket.getEncKdcRepPart()).isNotNull();
    }
}
