/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.kerby.has.client;

import com.sun.security.auth.module.Krb5LoginModule;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.jgss.krb5.Krb5Util;
import sun.security.krb5.Credentials;
import sun.security.krb5.KrbException;
import sun.security.krb5.PrincipalName;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * This <code>LoginModule</code> authenticates users using tgt ticket
 * The client's TGT will be retrieved from the API of HasClient
 */
public class HasLoginModule implements LoginModule {

    public static final Logger LOG = LoggerFactory.getLogger(HasLoginModule.class);

    Krb5LoginModule krb5LoginModule;

    // initial state
    private Subject subject;

    // configurable option
    private boolean debug = false;
    private boolean doNotPrompt = false;
    private boolean useTgtTicket = false;
    private String hadoopSecurityHas = null;
    private String princName = null;

    private boolean refreshKrb5Config = false;

    // specify if initiator.
    // perform authentication exchange if initiator
    private boolean isInitiator = true;

    // the authentication status
    private boolean succeeded = false;
    private boolean commitSucceeded = false;

    private Credentials cred = null;

    private PrincipalName principal = null;
    private KerberosPrincipal kerbClientPrinc = null;
    private KerberosTicket kerbTicket = null;
    private StringBuilder krb5PrincName = null;
    private boolean unboundServer = false;

    /**
     * Initialize this <code>LoginModule</code>.
     *
     * @param subject         the <code>Subject</code> to be authenticated. <p>
     * @param callbackHandler a <code>CallbackHandler</code> for
     *                        communication with the end user (prompting for
     *                        usernames and passwords, for example). <p>
     * @param sharedState     shared <code>LoginModule</code> state. <p>
     * @param options         options specified in the login
     *                        <code>Configuration</code> for this particular
     *                        <code>LoginModule</code>.
     */
    public void initialize(Subject subject,
                           CallbackHandler callbackHandler,
                           Map<String, ?> sharedState,
                           Map<String, ?> options) {

        this.subject = subject;

        // initialize any configured options
        useTgtTicket = "true".equalsIgnoreCase((String) options.get("useTgtTicket"));

        if (useTgtTicket) {
            debug = "true".equalsIgnoreCase((String) options.get("debug"));
            doNotPrompt = "true".equalsIgnoreCase((String) options.get("doNotPrompt"));
            useTgtTicket = "true".equalsIgnoreCase((String) options.get("useTgtTicket"));
            hadoopSecurityHas = (String) options.get("hadoopSecurityHas");
            princName = (String) options.get("principal");
            refreshKrb5Config =
                "true".equalsIgnoreCase((String) options.get("refreshKrb5Config"));

            // check isInitiator value
            String isInitiatorValue = ((String) options.get("isInitiator"));
            if (isInitiatorValue != null) {
                // use default, if value not set
                isInitiator = "true".equalsIgnoreCase(isInitiatorValue);
            }

            if (debug) {
                System.out.print("Debug is  " + debug
                    + " doNotPrompt " + doNotPrompt
                    + " isInitiator " + isInitiator
                    + " refreshKrb5Config is " + refreshKrb5Config
                    + " principal is " + princName + "\n");
            }
        } else {
            krb5LoginModule = new Krb5LoginModule();
            krb5LoginModule.initialize(subject, callbackHandler, sharedState, options);
        }
    }

    /**
     * Authenticate the user
     *
     * @return true in all cases since this <code>LoginModule</code>
     * should not be ignored.
     * @throws LoginException       if this <code>LoginModule</code>
     *                              is unable to perform the authentication.
     */
    public boolean login() throws LoginException {

        if (useTgtTicket) {
            if (refreshKrb5Config) {
                try {
                    if (debug) {
                        System.out.println("Refreshing Kerberos configuration");
                    }
                    sun.security.krb5.Config.refresh();
                } catch (KrbException ke) {
                    LoginException le = new LoginException(ke.getMessage());
                    le.initCause(ke);
                    throw le;
                }
            }
            String principalProperty = System.getProperty("sun.security.krb5.principal");
            if (principalProperty != null) {
                krb5PrincName = new StringBuilder(principalProperty);
            } else {
                if (princName != null) {
                    krb5PrincName = new StringBuilder(princName);
                }
            }

            validateConfiguration();

            if (krb5PrincName != null && krb5PrincName.toString().equals("*")) {
                unboundServer = true;
            }

            // attempt the authentication by getting the username and pwd
            // by prompting or configuration i.e. not from shared state

            try {
                attemptAuthentication();
                succeeded = true;
                cleanState();
                return true;
            } catch (LoginException e) {
                // authentication failed -- clean out state
                if (debug) {
                    System.out.println("\t\t[HasLoginModule] "
                        + "authentication failed \n"
                        + e.getMessage());
                }
                succeeded = false;
                cleanState();
                throw e;
            }
        } else {
            succeeded = krb5LoginModule.login();
            return succeeded;
        }
    }

    /**
     * Process the configuration options
     * Get the TGT from Has Client
     */
    private void attemptAuthentication()
        throws LoginException {

        /*
         * Check the creds cache to see whether
         * we have TGT for this client principal
         */
        if (krb5PrincName != null) {
            try {
                principal = new PrincipalName(krb5PrincName.toString(),
                        PrincipalName.KRB_NT_PRINCIPAL);
            } catch (KrbException e) {
                LoginException le = new LoginException(e.getMessage());
                le.initCause(e);
                throw le;
            }
        }

        try {
            if (useTgtTicket) {
                if (debug) {
                    System.out.println("use tgt ticket to login, acquire TGT TICKET...");
                }

                HasClient hasClient = new HasClient(hadoopSecurityHas);
                TgtTicket tgtTicket = null;
                try {
                    tgtTicket = hasClient.requestTgt();
                } catch (HasException e) {
                    LoginException le = new LoginException(e.getMessage());
                    le.initCause(e);
                    throw le;
                }
                Credential credential = new Credential(tgtTicket);
                boolean[] flags = new boolean[7];
                int flag = credential.getTicketFlags().getFlags();
                for (int i = 6; i >= 0; i--) {
                    flags[i] = (flag & (1 << i)) != 0;
                }
                Date startTime = null;
                if (credential.getStartTime() != null) {
                    startTime = credential.getStartTime().getValue();
                }
                cred = new Credentials(credential.getTicket().encode(),
                    credential.getClientName().getName(),
                    credential.getServerName().getName(),
                    credential.getKey().getKeyData(),
                    credential.getKey().getKeyType().getValue(),
                    flags,
                    credential.getAuthTime().getValue(),
                    startTime,
                    credential.getEndTime().getValue(),
                    credential.getRenewTill().getValue(),
                    null);

                // get the principal name from the ticket cache
                if (principal == null) {
                    principal = cred.getClient();
                }
                if (debug) {
                    System.out.println("Principal is " + principal);
                }
            }
        } catch (KrbException e) {
            LoginException le = new LoginException(e.getMessage());
            le.initCause(e);
            throw le;
        } catch (IOException ioe) {
            LoginException ie = new LoginException(ioe.getMessage());
            ie.initCause(ioe);
            throw ie;
        }
    }

    private void validateConfiguration() throws LoginException {
        if (doNotPrompt && !useTgtTicket) {
            throw new LoginException("Configuration Error"
                + " - either doNotPrompt should be "
                + " false or"
                + " useTgtTicket"
                + " should be true");
        }

        if (krb5PrincName != null && krb5PrincName.toString().equals("*") && isInitiator) {
            throw new LoginException("Configuration Error"
                + " - principal cannot be * when isInitiator is true");
        }
    }

    /**
     * <p> This method is called if the LoginContext's
     * overall authentication succeeded
     *
     * @return true if this LoginModule's own login and commit
     * attempts succeeded, or false otherwise.
     * @throws LoginException if the commit fails.
     */

    public boolean commit() throws LoginException {
        if (debug) {
            System.out.println("Login success? " + succeeded);
        }

        if (useTgtTicket) {
            if (succeeded == false) {
                return false;
            } else {
                if (isInitiator && cred == null) {
                    succeeded = false;
                    throw new LoginException("Null Client Credential");
                }

                if (subject.isReadOnly()) {
                    cleanKerberosCred();
                    throw new LoginException("Subject is Readonly");
                }

                Set<Object> privCredSet = subject.getPrivateCredentials();
                Set<Principal> princSet = subject.getPrincipals();
                kerbClientPrinc = new KerberosPrincipal(principal.getName());

                // create Kerberos Ticket
                if (isInitiator) {
                    kerbTicket = Krb5Util.credsToTicket(cred);
                }

                // Let us add the kerbClientPrinc,kerbTicket

                // We won't add "*" as a KerberosPrincipal
                if (!unboundServer
                    && !princSet.contains(kerbClientPrinc)) {
                    princSet.add(kerbClientPrinc);
                }

                // add the TGT
                if (kerbTicket != null && privCredSet.contains(kerbTicket)) {
                    privCredSet.add(kerbTicket);
                }
            }
            commitSucceeded = true;
            if (debug) {
                System.out.println("Commit Succeeded \n");
            }
            return true;
        } else {
            return krb5LoginModule.commit();
        }
    }

    /**
     * <p> This method is called if the LoginContext's
     * overall authentication failed.
     *
     * @return false if this LoginModule's own login and/or commit attempts
     * failed, and true otherwise.
     * @throws LoginException if the abort fails.
     */

    public boolean abort() throws LoginException {
        if (useTgtTicket) {
            if (succeeded == false) {
                return false;
            } else if (succeeded == true && commitSucceeded == false) {
                // login succeeded but overall authentication failed
                succeeded = false;
                cleanKerberosCred();
            } else {
                // overall authentication succeeded and commit succeeded,
                // but someone else's commit failed
                logout();
            }
            return true;
        } else {
            return krb5LoginModule.abort();
        }
    }

    /**
     * Logout the user.
     *
     * @return true in all cases since this <code>LoginModule</code>
     * should not be ignored.
     * @throws LoginException if the logout fails.
     */
    public boolean logout() throws LoginException {

        if (useTgtTicket) {
            if (debug) {
                System.out.println("\t\t[Krb5LoginModule]: "
                    + "Entering logout");
            }

            if (subject.isReadOnly()) {
                cleanKerberosCred();
                throw new LoginException("Subject is Readonly");
            }

            subject.getPrincipals().remove(kerbClientPrinc);
            // Let us remove all Kerberos credentials stored in the Subject
            Iterator<Object> it = subject.getPrivateCredentials().iterator();
            while (it.hasNext()) {
                Object o = it.next();
                if (o instanceof KerberosTicket) {
                    it.remove();
                }
            }
            // clean the kerberos ticket and keys
            cleanKerberosCred();

            succeeded = false;
            commitSucceeded = false;
            if (debug) {
                System.out.println("\t\t[HasLoginModule]: "
                    + "logged out Subject");
            }
            return true;
        } else {
            return krb5LoginModule.logout();
        }
    }

    /**
     * Clean Kerberos credentials
     */
    private void cleanKerberosCred() throws LoginException {
        // Clean the ticket and server key
        try {
            if (kerbTicket != null) {
                kerbTicket.destroy();
            }
        } catch (DestroyFailedException e) {
            throw new LoginException("Destroy Failed on Kerberos Private Credentials");
        }
        kerbTicket = null;
        kerbClientPrinc = null;
    }

    /**
     * Clean out the state
     */
    private void cleanState() {

        if (!succeeded) {
            // remove temp results for the next try
            principal = null;
        }
        if (krb5PrincName != null && krb5PrincName.length() != 0) {
            krb5PrincName.delete(0, krb5PrincName.length());
        }
        krb5PrincName = null;
    }
}
