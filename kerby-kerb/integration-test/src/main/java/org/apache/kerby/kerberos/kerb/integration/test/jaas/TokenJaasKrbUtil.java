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

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * JAAS utilities for token login.
 */
public class TokenJaasKrbUtil {

    /**
     * Login using token cache.
     *
     * @param principal The client principal name
     * @param tokenCache the token cache for login
     * @param armorCache the armor cache for fast preauth
     * @param ccache The file to store the tgt ticket
     * @return the authenticated Subject
     * @throws LoginException e
     */
    public static Subject loginUsingToken(
            String principal, File tokenCache, File armorCache, File ccache)
            throws LoginException {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new KerberosPrincipal(principal));

        Subject subject = new Subject(false, principals,
                new HashSet<Object>(), new HashSet<Object>());
        Configuration conf = useTokenCache(principal, tokenCache, armorCache, ccache);
        String confName = "TokenCacheConf";
        LoginContext loginContext = new LoginContext(confName, subject, null, conf);
        loginContext.login();
        return loginContext.getSubject();
    }

    /**
     * Login using token string.
     *
     * @param principal The client principal name
     * @param tokenStr the token string for login
     * @param armorCache the armor cache for fast preauth
     * @param ccache The file to store the tgt ticket
     * @return the authenticated Subject
     * @throws LoginException e
     */
    public static Subject loginUsingToken(
            String principal, String tokenStr, File armorCache, File ccache)
            throws LoginException {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new KerberosPrincipal(principal));

        Subject subject = new Subject(false, principals,
                new HashSet<Object>(), new HashSet<Object>());
        Configuration conf = useTokenStr(principal, tokenStr, armorCache, ccache);
        String confName = "TokenStrConf";
        LoginContext loginContext = new LoginContext(confName, subject, null, conf);
        loginContext.login();
        return loginContext.getSubject();
    }

    private static Configuration useTokenCache(String principal, File tokenCache,
                                              File armorCache, File tgtCache) {
        return new TokenJaasConf(principal, tokenCache, armorCache, tgtCache);
    }

    private static Configuration useTokenStr(String principal, String tokenStr,
                                            File armorCache, File tgtCache) {
        return new TokenJaasConf(principal, tokenStr, armorCache, tgtCache);
    }

    /**
     * Token Jaas config.
     */
    static class TokenJaasConf extends Configuration {
        private String principal;
        private File tokenCache;
        private String tokenStr;
        private File armorCache;
        private File ccache;

        public TokenJaasConf(String principal, File tokenCache, File armorCache, File ccache) {
            this.principal = principal;
            this.tokenCache = tokenCache;
            this.armorCache = armorCache;
            this.ccache = ccache;
        }

        public TokenJaasConf(String principal, String tokenStr, File armorCache, File ccache) {
            this.principal = principal;
            this.tokenStr = tokenStr;
            this.armorCache = armorCache;
            this.ccache = ccache;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            Map<String, String> options = new HashMap<String, String>();
            options.put(TokenAuthLoginModule.PRINCIPAL, principal);
            if (tokenCache != null) {
                options.put(TokenAuthLoginModule.TOKEN_CACHE, tokenCache.getAbsolutePath());
            } else if (tokenStr != null) {
                options.put(TokenAuthLoginModule.TOKEN, tokenStr);
            }
            options.put(TokenAuthLoginModule.ARMOR_CACHE, armorCache.getAbsolutePath());
            options.put(TokenAuthLoginModule.CREDENTIAL_CACHE, ccache.getAbsolutePath());

            return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(
                            "org.apache.kerby.kerberos.kerb.integration.test.jaas.TokenAuthLoginModule",
                            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                            options)};
        }
    }
}
