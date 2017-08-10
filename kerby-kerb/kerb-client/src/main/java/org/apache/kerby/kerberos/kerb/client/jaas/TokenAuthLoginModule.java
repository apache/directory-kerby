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
package org.apache.kerby.kerberos.kerb.client.jaas;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbTokenClient;
import org.apache.kerby.kerberos.kerb.common.PrivateKeyReader;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.base.KrbToken;
import org.apache.kerby.kerberos.kerb.type.base.TokenFormat;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.kerberos.provider.token.JwtAuthToken;
import org.apache.kerby.kerberos.provider.token.JwtTokenEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;

/**
 * This <code>LoginModule</code> authenticates users using token.
 * tokenStr: token-string
 * tokenCache: token-cache-file
 * armorCache: armor-cache-file
 */
public class TokenAuthLoginModule implements LoginModule {
    public static final String PRINCIPAL = "principal";
    public static final String TOKEN = "token";
    public static final String TOKEN_CACHE = "tokenCache";
    public static final String ARMOR_CACHE = "armorCache";
    public static final String CREDENTIAL_CACHE = "credentialCache";
    public static final String SIGN_KEY_FILE = "signKeyFile";

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
    private KrbToken krbToken = null;
    private File armorCache;
    private File cCache;
    private File signKeyFile;

    private TgtTicket tgtTicket;

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
        if ((String) options.get(ARMOR_CACHE) != null) {
            armorCache = new File((String) options.get(ARMOR_CACHE));
        }
        if ((String) options.get(CREDENTIAL_CACHE) != null) {
            cCache = new File((String) options.get(CREDENTIAL_CACHE));
        }
        if ((String) options.get(SIGN_KEY_FILE) != null) {
            signKeyFile = new File((String) options.get(SIGN_KEY_FILE));
        }
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

        if (!succeeded) {
            return false;
        } else {
            KerberosTicket ticket = null;
            try {
                EncKdcRepPart encKdcRepPart = tgtTicket.getEncKdcRepPart();
                boolean[] flags = new boolean[7];
                int flag = encKdcRepPart.getFlags().getFlags();
                for (int i = 6; i >= 0; i--) {
                    flags[i] = (flag & (1 << i)) != 0;
                }
                Date startTime = null;
                if (encKdcRepPart.getStartTime() != null) {
                    startTime = encKdcRepPart.getStartTime().getValue();
                }

                ticket = new KerberosTicket(tgtTicket.getTicket().encode(),
                    new KerberosPrincipal(tgtTicket.getClientPrincipal().getName()),
                    new KerberosPrincipal(tgtTicket.getEncKdcRepPart().getSname().getName()),
                    encKdcRepPart.getKey().getKeyData(),
                    encKdcRepPart.getKey().getKeyType().getValue(),
                    flags,
                    encKdcRepPart.getAuthTime().getValue(),
                    startTime,
                    encKdcRepPart.getEndTime().getValue(),
                    encKdcRepPart.getRenewTill().getValue(),
                    null
                );
            } catch (IOException e) {
                LOG.error("Commit Failed. " + e.toString());
            }
            subject.getPrivateCredentials().add(ticket);
            if (princName != null) {
                subject.getPrincipals().add(new KerberosPrincipal(princName));
            }
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

        for (Principal principal: subject.getPrincipals()) {
            if (principal.getName().equals(princName)) {
                subject.getPrincipals().remove(principal);
            }
        }
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

        if (armorCache == null) {
            throw new LoginException("An armor cache must be specified via the armorCache configuration option");
        }

        if (cCache == null) {
            LOG.info("No credential cache was specified via 'credentialCache'. "
                     + "The TGT will be stored internally instead");
        }

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

        krbToken = new KrbToken();

        // Sign the token.
        if (signKeyFile != null) {
            try {
                TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();
                try {
                    authToken = tokenDecoder.decodeFromString(tokenStr);
                } catch (IOException e) {
                    LOG.error("Token decode failed. " + e.toString());
                }
                TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();

                if (tokenEncoder instanceof JwtTokenEncoder) {
                    PrivateKey signKey = null;
                    try (InputStream is = Files.newInputStream(signKeyFile.toPath())) {
                        signKey = PrivateKeyReader.loadPrivateKey(is);
                    } catch (IOException e) {
                        LOG.error("Failed to load private key from file: "
                                + signKeyFile.getName());
                    } catch (Exception e) {
                        LOG.error(e.toString());
                    }

                    ((JwtTokenEncoder) tokenEncoder).setSignKey((RSAPrivateKey) signKey);
                }

                krbToken.setTokenValue(tokenEncoder.encodeAsBytes(authToken));
            } catch (KrbException e) {
                throw new RuntimeException("Failed to encode AuthToken", e);
            }
        } else {
            // Otherwise just write out the token (which could be already signed)
            krbToken.setTokenValue(tokenStr.getBytes());

            if (authToken == null) {
                try {
                    JWT jwt = JWTParser.parse(tokenStr);
                    authToken = new JwtAuthToken(jwt.getJWTClaimsSet());
                } catch (ParseException e) {
                    // Invalid JWT encoding
                    throw new RuntimeException("Failed to parse JWT token string", e);
                }
            }
        }

        krbToken.setInnerToken(authToken);
        krbToken.setTokenType();
        krbToken.setTokenFormat(TokenFormat.JWT);

        KrbClient krbClient = null;
        try {
            File confFile = new File(System.getProperty("java.security.krb5.conf"));
            KrbConfig krbConfig = new KrbConfig();
            krbConfig.addKrb5Config(confFile);
            krbClient = new KrbClient(krbConfig);
            krbClient.init();
        } catch (KrbException | IOException e) {
            LOG.error("KrbClient init failed. " + e.toString());
        }

        KrbTokenClient tokenClient = new KrbTokenClient(krbClient);
        try {
            tgtTicket = tokenClient.requestTgt(krbToken,
                armorCache.getAbsolutePath());
        } catch (KrbException e) {
            throwWith("Failed to do login with token: " + tokenStr, e);
            return false;
        }

        // Write the TGT out to the credential cache if it is specified in the configuration
        if (cCache != null) {
            try {
                cCache = makeTgtCache();
            } catch (IOException e) {
                LOG.error("Failed to make tgtCache. " + e.toString());
            }
            try {
                if (krbClient != null) {
                    krbClient.storeTicket(tgtTicket, cCache);
                }
            } catch (KrbException e) {
                LOG.error("Failed to store tgtTicket to " + cCache.getName());
            }
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
            boolean delete = cCache.delete();
            if (!delete) {
                throw new RuntimeException("File delete error!");
            }
        }
    }

    private void throwWith(String error, Exception cause) throws LoginException {
        LoginException le = new LoginException(error);
        le.initCause(cause);
        throw le;
    }
}
