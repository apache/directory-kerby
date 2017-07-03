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

import org.apache.kerby.kerberos.kerb.server.KerberosClientExceptionAction;
import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import java.io.File;
import java.security.Principal;
import java.util.Set;

/**
 * Test login with token when token preauth is allowed by kdc.
 */
public class TokenLoginWithTokenPreauthEnabledTest extends TokenLoginTestBase {

    @Override
    protected Boolean isTokenPreauthAllowed() {
        return true;
    }

    @Test
    public void testLoginWithTokenStr() throws Exception {
        super.testLoginWithTokenStr();
    }

    @Test
    public void testLoginWithTokenCache() throws Exception {
        super.testLoginWithTokenCache();
    }

    @Test
    public void testLoginWithTokenCacheGSS() throws Exception {
        Subject subject = super.testLoginWithTokenCacheAndRetSubject();
        Set<Principal> clientPrincipals = subject.getPrincipals();

        // Get the service ticket
        KerberosClientExceptionAction action =
                new KerberosClientExceptionAction(clientPrincipals.iterator().next(),
                        getServerPrincipal());

        byte[] kerberosToken = (byte[]) Subject.doAs(subject, action);
        Assert.assertNotNull(kerberosToken);
    }

    @Test
    public void testUntrustedSignature() throws Exception {
        String tokenStr = createTokenAndArmorCache();
        File signKeyFile = new File(this.getClass().getResource("/kdckeytest.pem").getPath());
        try {
            loginClientUsingTokenStr(tokenStr, getArmorCache(), getTGTCache(), signKeyFile);
            Assert.fail("Failure expected on a signature that is not trusted");
        } catch (LoginException ex) { //NOPMD
            // expected
        }
    }

    @Test
    public void testUnsignedToken() throws Exception {
        String tokenStr = createTokenAndArmorCache();
        try {
            loginClientUsingTokenStr(tokenStr, getArmorCache(), getTGTCache(), null);
            Assert.fail("Failure expected on an unsigned token");
        } catch (LoginException ex) { //NOPMD
            // expected
        }
    }
}
