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
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

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
        new HashMap<>();

    static {
        String jaasEnvVar = System.getenv("HADOOP_JAAS_DEBUG");
        if (jaasEnvVar != null && "true".equalsIgnoreCase(jaasEnvVar)) {
            BASIC_JAAS_OPTIONS.put("debug", String.valueOf(ENABLE_DEBUG));
        }
    }

    private static final Map<String, String> TICKET_KERBEROS_OPTIONS =
        new HashMap<>();

    static {
        TICKET_KERBEROS_OPTIONS.put("doNotPrompt", "true");
        TICKET_KERBEROS_OPTIONS.put("useTgtTicket", "true");
        TICKET_KERBEROS_OPTIONS.putAll(BASIC_JAAS_OPTIONS);
    }

    private static final AppConfigurationEntry TICKET_KERBEROS_LOGIN =
        new AppConfigurationEntry(getKrb5LoginModuleName(),
            AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL,
            TICKET_KERBEROS_OPTIONS);
}
