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
package org.apache.kerby.has.common.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * JAAS utilities for Has login.
 */
public class HasJaasLoginUtil {
    public static final Logger LOG = LoggerFactory.getLogger(HasJaasLoginUtil.class);

    public static final boolean ENABLE_DEBUG = true;

    private static String getKrb5LoginModuleName() {
        return System.getProperty("java.vendor").contains("IBM")
            ? "com.ibm.security.auth.module.Krb5LoginModule"
            : "org.apache.kerby.has.client.HasLoginModule";
    }

    /**
     * Log a user in from a tgt ticket.
     *
     * @throws IOException
     */
    public static synchronized Subject loginUserFromTgtTicket(String hadoopSecurityHas) throws IOException {

        TICKET_KERBEROS_OPTIONS.put("hadoopSecurityHas", hadoopSecurityHas);
        Subject subject = new Subject();
        Configuration conf = new HasJaasConf();
        String confName = "ticket-kerberos";
        LoginContext loginContext = null;
        try {
            loginContext = new LoginContext(confName, subject, null, conf);
        } catch (LoginException e) {
            throw new IOException("Fail to create LoginContext for " + e);
        }
        try {
            loginContext.login();
            LOG.info("Login successful for user "
                + subject.getPrincipals().iterator().next().getName());
        } catch (LoginException e) {
            throw new IOException("Login failure for " + e);
        }
        return loginContext.getSubject();
    }

    /**
     * Has Jaas config.
     */
    static class HasJaasConf extends Configuration {
        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {

            return new AppConfigurationEntry[]{
                TICKET_KERBEROS_LOGIN};
        }
    }

    private static final Map<String, String> BASIC_JAAS_OPTIONS =
        new HashMap<String, String>();

    static {
        String jaasEnvVar = System.getenv("HADOOP_JAAS_DEBUG");
        if (jaasEnvVar != null && "true".equalsIgnoreCase(jaasEnvVar)) {
            BASIC_JAAS_OPTIONS.put("debug", String.valueOf(ENABLE_DEBUG));
        }
    }

    private static final Map<String, String> TICKET_KERBEROS_OPTIONS =
        new HashMap<String, String>();

    static {
        TICKET_KERBEROS_OPTIONS.put("doNotPrompt", "true");
        TICKET_KERBEROS_OPTIONS.put("useTgtTicket", "true");
        TICKET_KERBEROS_OPTIONS.putAll(BASIC_JAAS_OPTIONS);
    }

    private static final AppConfigurationEntry TICKET_KERBEROS_LOGIN =
        new AppConfigurationEntry(getKrb5LoginModuleName(),
            AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL,
            TICKET_KERBEROS_OPTIONS);


     public static Subject loginUsingTicketCache(
        String principal, File cacheFile) throws IOException {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new KerberosPrincipal(principal));

        Subject subject = new Subject(false, principals,
            new HashSet<Object>(), new HashSet<Object>());

        Configuration conf = useTicketCache(principal, cacheFile);
        String confName = "TicketCacheConf";
         LoginContext loginContext = null;
         try {
             loginContext = new LoginContext(confName, subject, null, conf);
         } catch (LoginException e) {
             throw new IOException("Faill to create LoginContext for " + e);
         }
         try {
             loginContext.login();
             LOG.info("Login successful for user "
                 + subject.getPrincipals().iterator().next().getName());
         } catch (LoginException e) {
             throw new IOException("Login failure for " + e);
         }
         return loginContext.getSubject();
    }

    public static Subject loginUsingKeytab(
        String principal, File keytabFile) throws IOException {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new KerberosPrincipal(principal));

        Subject subject = new Subject(false, principals,
            new HashSet<Object>(), new HashSet<Object>());

        Configuration conf = useKeytab(principal, keytabFile);
        String confName = "KeytabConf";
        LoginContext loginContext = null;
        try {
            loginContext = new LoginContext(confName, subject, null, conf);
        } catch (LoginException e) {
            throw new IOException("Fail to create LoginContext for " + e);
        }
        try {
            loginContext.login();
             LOG.info("Login successful for user "
                + subject.getPrincipals().iterator().next().getName());
        } catch (LoginException e) {
            throw new IOException("Login failure for " + e);
        }
        return loginContext.getSubject();
    }

    public static LoginContext loginUsingKeytabReturnContext(
        String principal, File keytabFile) throws IOException {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new KerberosPrincipal(principal));

        Subject subject = new Subject(false, principals,
            new HashSet<Object>(), new HashSet<Object>());

        Configuration conf = useKeytab(principal, keytabFile);
        String confName = "KeytabConf";
        LoginContext loginContext = null;
        try {
            loginContext = new LoginContext(confName, subject, null, conf);
        } catch (LoginException e) {
            throw new IOException("Fail to create LoginContext for " + e);
        }
        try {
            loginContext.login();
            LOG.info("Login successful for user "
                + subject.getPrincipals().iterator().next().getName());
        } catch (LoginException e) {
            throw new IOException("Login failure for " + e);
        }
        return loginContext;
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

        TicketCacheJaasConf(String principal, File clientCredentialFile) {
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
            options.putAll(BASIC_JAAS_OPTIONS);

            return new AppConfigurationEntry[]{
                new AppConfigurationEntry(getKrb5LoginModuleName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                    options)};
        }
    }

    static class KeytabJaasConf extends Configuration {
        private String principal;
        private File keytabFile;

        KeytabJaasConf(String principal, File keytab) {
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
            options.putAll(BASIC_JAAS_OPTIONS);

            return new AppConfigurationEntry[]{
                new AppConfigurationEntry(getKrb5LoginModuleName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                    options)};
        }
    }
}
