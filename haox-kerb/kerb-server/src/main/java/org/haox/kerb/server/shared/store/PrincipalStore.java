package org.haox.kerb.server.shared.store;

import org.apache.directory.server.kerberos.changepwd.exceptions.ChangePasswordException;

import javax.security.auth.kerberos.KerberosPrincipal;


/**
 * The store interface used by Kerberos services.
 */
public interface PrincipalStore
{

    /**
     * Change a principal's password.
     * @param byPrincipal the principal which is changing the password for the forPrincipal
     * @param forPrincipal the principal whose password is being set or changed
     * @param newPassword the new password
     * @param isInitialTicket tells if the ticket is a freshly obtained ticket
     * @throws Exception
     */
    void changePassword(KerberosPrincipal byPrincipal, KerberosPrincipal forPrincipal, String newPassword,
                        boolean isInitialTicket) throws ChangePasswordException;


    /**
     * Get a {@link org.apache.directory.server.kerberos.shared.store.PrincipalStoreEntry} given a Kerberos principal.
     *
     * @param principal
     * @return The {@link org.apache.directory.server.kerberos.shared.store.PrincipalStoreEntry} for the given Kerberos principal.
     * @throws Exception
     */
    PrincipalStoreEntry getPrincipal(KerberosPrincipal principal) throws Exception;
}
