package org.haox.kerb.server.sam;

import javax.security.auth.kerberos.KerberosKey;


/**
 * Checks the integrity of a kerberos key to decode-decrypt an encrypted
 * generalized timestamp representing the pre-auth data.
 */
public interface KeyIntegrityChecker
{
    /**
     * Checks the integrity of a KerberosKey to decrypt-decode and compare an
     * encrypted encoded generalized timestamp representing the preauth data.
     *
     * @param preauthData the generalized timestamp encrypted with client hotp
     * generated KerberosKey
     * @param key the KerberosKey generated from server side hotp value
     * @return true if the key can decrypt-decode and make sense out of the
     * timestamp verifying that it is in skew, false otherwise
     */
    boolean checkKeyIntegrity(byte[] preauthData, KerberosKey key);
}
