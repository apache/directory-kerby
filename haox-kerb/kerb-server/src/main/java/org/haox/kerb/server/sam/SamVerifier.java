package org.haox.kerb.server.sam;

import org.haox.kerb.spec.type.common.SamType;

import javax.naming.directory.DirContext;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;


/**
 * Single-use Authentication Mechanism verifier (subsystem) interface.
 * SamVerifiers are modules that can be configured and are dynamically
 * loaded as needed.  Implementations have a few requirements and things
 * implementors should know:
 *
 * <ul>
 *   <li>A public default constructor is required,</li>
 *   <li>after instantitation environment properties are supplied,</li>
 *   <li>next the KeyIntegrityChecker is set for the verifier,</li>
 *   <li>finally the verifier is started up by calling startup(),
 *       incidentally this is where all initialization work should be
 *       done using the environment properties supplied.
 *   </li>
 * </ul>
 *
 */
public interface SamVerifier
{
    /**
     * Starts one of many pluggable SAM type subsystem.
     * 
     * @throws SamException
     */
    void startup() throws SamException;


    /**
     * Shuts down one of many pluggable SAM type subsystem.
     */
    void shutdown();


    /**
     * SamVerifiers require a KeyIntegrityChecker to calculate the integrity of
     * a generated KerberosKey.  The Kerberos service exposes this interface
     * and supplies it to the verifier to check generated keys to conduct the
     * verification workflow.
     *
     * @param keyChecker The integrity checker that validates whether or not a
     * key can decrypt-decode preauth data (an encryped-encoded generalized
     * timestamp).
     */
    void setIntegrityChecker(KeyIntegrityChecker keyChecker);


    /**
     * Verifies the single use password supplied.
     *
     * @param principal The kerberos principal to use.
     * @param sad Single-use authentication data (encrypted generalized timestamp).
     * @return The {@link javax.security.auth.kerberos.KerberosKey}.
     * @throws SamException 
     */
    KerberosKey verify(KerberosPrincipal principal, byte[] sad) throws SamException;


    /**
     * Gets the registered SAM algorithm type implemented by this SamVerifier.
     *
     * @return The type value for the SAM algorithm used to verify the SUP.
     */
    SamType getSamType();


    /**
     * Sets the user context where users are stored for the primary realm.
     *  
     * @param userContext
     */
    void setUserContext(DirContext userContext);
}
