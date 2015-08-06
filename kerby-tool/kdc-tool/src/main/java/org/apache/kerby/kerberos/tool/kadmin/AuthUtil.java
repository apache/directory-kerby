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
package org.apache.kerby.kerberos.tool.kadmin;

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

public class AuthUtil {

    public static boolean enableDebug = true;

    private static String getKrb5LoginModuleName() {
        return System.getProperty("java.vendor").contains("IBM")
            ? "com.ibm.security.auth.module.Krb5LoginModule"
            : "com.sun.security.auth.module.Krb5LoginModule";
    }

    public static Subject loginUsingTicketCache(
        String principal, File cacheFile) throws LoginException {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new KerberosPrincipal(principal));

        Subject subject = new Subject(false, principals,
            new HashSet<Object>(), new HashSet<Object>());

        Configuration conf = useTicketCache(principal, cacheFile);
        String confName = "TicketCacheConf";
        LoginContext loginContext = new LoginContext(confName, subject, null, conf);
        loginContext.login();
        return loginContext.getSubject();
    }

    public static Subject loginUsingKeytab(
        String principal, File keytabFile) throws LoginException {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new KerberosPrincipal(principal));

        Subject subject = new Subject(false, principals,
            new HashSet<Object>(), new HashSet<Object>());

        Configuration conf = useKeytab(principal, keytabFile);
        String confName = "KeytabConf";
        LoginContext loginContext = new LoginContext(confName, subject, null, conf);
        loginContext.login();
        return loginContext.getSubject();
    }

    public static Configuration useTicketCache(String principal,
                                               File credentialFile) {
        return new TicketCacheJaasConf(principal, credentialFile);
    }

    public static Configuration useKeytab(String principal, File keytabFile) {
        return new KeytabJaasConf(principal, keytabFile);
    }

    static class TicketCacheJaasConf extends Configuration {
        private String principal;
        private File clientCredentialFile;

        public TicketCacheJaasConf(String principal, File clientCredentialFile) {
            this.principal = principal;
            this.clientCredentialFile = clientCredentialFile;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            Map<String, String> options = new HashMap<String, String>();
            options.put("principal", principal);
            options.put("storeKey", "false");
            options.put("doNotPrompt", "false");
            options.put("useTicketCache", "true");
            options.put("renewTGT", "true");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", "true");
            options.put("ticketCache", clientCredentialFile.getAbsolutePath());
            options.put("debug", String.valueOf(enableDebug));

            return new AppConfigurationEntry[]{
                new AppConfigurationEntry(getKrb5LoginModuleName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                    options)};
        }
    }

    static class KeytabJaasConf extends Configuration {
        private String principal;
        private File keytabFile;

        public KeytabJaasConf(String principal, File keytab) {
            this.principal = principal;
            this.keytabFile = keytab;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            Map<String, String> options = new HashMap<String, String>();
            options.put("keyTab", keytabFile.getAbsolutePath());
            options.put("principal", principal);
            options.put("useKeyTab", "true");
            options.put("storeKey", "true");
            options.put("doNotPrompt", "true");
            options.put("renewTGT", "false");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", "true");
            options.put("debug", String.valueOf(enableDebug));

            return new AppConfigurationEntry[]{
                new AppConfigurationEntry(getKrb5LoginModuleName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                    options)};
        }
    }
}
