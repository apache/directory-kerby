package org.apache.kerby.kerberos.kerb.gss.impl;

import org.ietf.jgss.GSSException;
import sun.security.jgss.GSSCaller;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.*;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Set;

/**
 * Utility functions to deal with credentials in Context
 */
public class CredUtils {

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
            KerberosKey[] keys = tab.getKeys(principal);
            if (keys != null && keys.length > 0) {
                return tab;
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
