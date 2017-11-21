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
package org.apache.kerby.kerberos.kerb.gss.impl;

import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.security.jgss.GSSCaller;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Set;

/**
 * Utility functions to deal with credentials in Context
 */
public class CredUtils {

    private static final Logger LOG = LoggerFactory.getLogger(CredUtils.class);

    public static <T> Set<T> getContextPrivateCredentials(Class<T> credentialType, AccessControlContext acc) {
        Subject subject = Subject.getSubject(acc);
        Set<T> creds = subject.getPrivateCredentials(credentialType);
        return creds;
    }

    public static <T> Set<T> getContextCredentials(final Class<T> credentialType) throws GSSException {
        final AccessControlContext acc = AccessController.getContext();
        try {
            return AccessController.doPrivileged(
                    new PrivilegedExceptionAction<Set<T>>() {
                        public Set<T> run() throws Exception {
                            return CredUtils.getContextPrivateCredentials(credentialType, acc);
                        }
                    });
        } catch (PrivilegedActionException e) {
            throw new GSSException(GSSException.NO_CRED, -1, "Get credential from context failed");
        }
    }

    public static Set<KerberosKey> getKerberosKeysFromContext(GSSCaller caller,
                                                              final String clientName,
                                                              final String serverName) throws GSSException {
        return getContextCredentials(KerberosKey.class);
    }

    public static KerberosTicket getKerberosTicketFromContext(GSSCaller caller,
                                                              final String clientName,
                                                              final String serverName) throws GSSException {
        Set<KerberosTicket> tickets = getContextCredentials(KerberosTicket.class);
        for (KerberosTicket ticket : tickets) {
            if (ticket.isCurrent() && (serverName == null || ticket.getServer().getName().equals(serverName))
                    && (clientName == null || ticket.getClient().getName().equals(clientName))) {
                return ticket;
            }
        }
        return null;
    }

    public static KeyTab getKeyTabFromContext(KerberosPrincipal principal) throws GSSException {
        Set<KeyTab> tabs = getContextCredentials(KeyTab.class);
        for (KeyTab tab : tabs) {
            // Use the supplied principal
            KerberosPrincipal princ = principal;
            if (princ == null) {
                // fall back to the principal of the KeyTab (if JDK 1.8) if none is supplied
                try {
                    Method m = tab.getClass().getDeclaredMethod("getPrincipal");
                    princ = (KerberosPrincipal) m.invoke(tab);
                } catch (NoSuchMethodException | SecurityException | IllegalAccessException
                    | IllegalArgumentException | InvocationTargetException e) {
                    LOG.info("Can't get a principal from the keytab", e);
                }
            }

            if (princ != null) {
                KerberosKey[] keys = tab.getKeys(princ);
                if (keys != null && keys.length > 0) {
                    return tab;
                }
            }
        }
        return null;
    }

    public static void addCredentialToSubject(final KerberosTicket ticket) throws GSSException {
        final AccessControlContext acc = AccessController.getContext();

        final Subject subject = AccessController.doPrivileged(
                new java.security.PrivilegedAction<Subject>() {
                    public Subject run() {
                        return Subject.getSubject(acc);
                    }
                });

        AccessController.doPrivileged(
                new java.security.PrivilegedAction<Void>() {
                    public Void run() {
                        subject.getPrivateCredentials().add(ticket);
                        return null;
                    }
                });
    }

    public static void checkPrincipalPermission(String principalName, String action) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            ServicePermission sp = new ServicePermission(principalName, action);
            sm.checkPermission(sp);
        }
    }
}
