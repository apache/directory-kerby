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
package org.apache.kerby.kerberos.kerb.integration.test.jaas;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.client.Krb5Conf;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.base.KrbToken;
import org.apache.kerby.kerberos.kerb.spec.base.TokenFormat;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.File;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

/**
 * This <code>LoginModule</code> authenticates users using token.
 * tokenStr: token-string
 * tokenCache: token-cache-file
 * armorCache: armor-cache-file
 */
public class TokenAuthLoginModule implements LoginModule {
    private static final Logger LOG = LoggerFactory.getLogger(TokenAuthLoginModule.class);

    /** initial state*/
    private Subject subject;

    /** configurable option*/
    private String tokenCacheName = null;

    /** the authentication status*/
    private boolean succeeded = false;
    private boolean commitSucceeded = false;

    private String princName = null;
    private String tokenStr = null;
    private AuthToken authToken = null;
    KrbToken krbToken = null;
    private File armorCache;
    private File cCache;
    public static final String PRINCIPAL = "principal";
    public static final String TOKEN = "token";
    public static final String TOKEN_CACHE = "tokenCache";
    public static final String ARMOR_CACHE = "armorCache";
    public static final String CREDENTIAL_CACHE = "credentialCache";

    /**
     * {@inheritDoc}
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {

        this.subject = subject;
        /** initialize any configured options*/
        princName = (String) options.get(PRINCIPAL);
        tokenStr = (String) options.get(TOKEN);
        tokenCacheName = (String) options.get(TOKEN_CACHE);
        armorCache = new File((String) options.get(ARMOR_CACHE));
        cCache = new File((String) options.get(CREDENTIAL_CACHE));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean login() throws LoginException {
        validateConfiguration();

        succeeded = tokenLogin();
        return succeeded;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean commit() throws LoginException {

        if (succeeded == false) {
            return false;
        } else {
            subject.getPublicCredentials().add(krbToken);
        }
        commitSucceeded = true;
        LOG.info("Commit Succeeded \n");
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean abort() throws LoginException {
        if (succeeded == false) {
            return false;
        } else if (succeeded == true && commitSucceeded == false) {
            // login succeeded but overall authentication failed
            succeeded = false;
        } else {
            // overall authentication succeeded and commit succeeded,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean logout() throws LoginException {
        LOG.info("\t\t[TokenAuthLoginModule]: Entering logout");

        if (subject.isReadOnly()) {
            throw new LoginException("Subject is Readonly");
        }

        subject.getPrincipals().remove(princName);
        // Let us remove all Kerberos credentials stored in the Subject
        Iterator<Object> it = subject.getPrivateCredentials().iterator();
        while (it.hasNext()) {
            Object o = it.next();
            if (o instanceof KrbToken) {
                it.remove();
            }
        }

        cleanup();

        succeeded = false;
        commitSucceeded = false;

        LOG.info("\t\t[TokenAuthLoginModule]: logged out Subject");
        return true;
    }

    private void validateConfiguration() throws LoginException {

        String error = "";
        if (tokenStr == null && tokenCacheName == null) {
            error = "useToken is specified but no token or token cache is provided";
        } else if (tokenStr != null && tokenCacheName != null) {
            error = "either token or token cache should be provided but not both";
        }

        if (!error.isEmpty()) {
            throw new LoginException(error);
        }
    }

    private boolean tokenLogin() throws LoginException {
        if (tokenStr == null) {
            tokenStr = TokenCache.readToken(tokenCacheName);
            if (tokenStr == null) {
                throw new LoginException("No valid token was found in token cache: " + tokenCacheName);
            }
        }
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();
        try {
            authToken = tokenDecoder.decodeFromString(tokenStr);
        } catch (IOException e) {
            e.printStackTrace();
        }
        krbToken = new KrbToken(authToken, TokenFormat.JWT);
        KrbClient krbClient = null;
        try {
            File confFile = new File(System.getProperty(Krb5Conf.KRB5_CONF));
            KrbConfig krbConfig = new KrbConfig();
            krbConfig.addIniConfig(confFile);
            krbClient = new KrbClient(krbConfig);
            krbClient.init();
        } catch (KrbException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        TgtTicket tgtTicket = null;
        try {
            tgtTicket = krbClient.requestTgtWithToken(krbToken, armorCache.getAbsolutePath());
        } catch (KrbException e) {
            throwWith("Failed to do login with token: " + tokenStr, e);
            return false;
        }

        try {
            cCache = makeTgtCache();
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            krbClient.storeTicket(tgtTicket, cCache);
        } catch (KrbException e) {
            e.printStackTrace();
        }
        return true;
    }

    private File makeTgtCache() throws IOException {

        if (!cCache.exists() && !cCache.createNewFile()) {
            throw new IOException("Failed to create tgtcache file "
                    + cCache.getAbsolutePath());
        }
        cCache.setExecutable(false);
        cCache.setReadable(true);
        cCache.setWritable(true);
        return cCache;
    }

    private void cleanup() {
        if (cCache != null && cCache.exists()) {
            cCache.delete();
        }
    }

    private void throwWith(String error, Exception cause) throws LoginException {
        LoginException le = new LoginException(error);
        le.initCause(cause);
        throw le;
    }
}
