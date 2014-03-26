package org.haox.kerb.server.shared.crypto.encryption;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbFactory;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;


/**
 * A factory class for producing {@link javax.security.auth.kerberos.KerberosKey}'s.  For a list of desired cipher
 * types, Kerberos string-to-key functions are used to derive keys for DES-, DES3-, AES-,
 * and RC4-based encryption types.
 *
 */
public class KerberosKeyFactory
{
    /** A map of default encryption types mapped to cipher names. */
    public static final Map<EncryptionType, String> DEFAULT_CIPHERS;

    static
    {
        Map<EncryptionType, String> map = new HashMap<EncryptionType, String>();

        map.put( EncryptionType.DES_CBC_MD5, "DES" );
        map.put( EncryptionType.DES3_CBC_SHA1_KD, "DESede" );
        map.put( EncryptionType.RC4_HMAC, "ArcFourHmac" );
        map.put( EncryptionType.AES128_CTS_HMAC_SHA1_96, "AES128" );
        map.put( EncryptionType.AES256_CTS_HMAC_SHA1_96, "AES256" );

        DEFAULT_CIPHERS = Collections.unmodifiableMap( map );
    }


    /**
     * Get a map of KerberosKey's for a given principal name and passphrase.  The default set
     * of encryption types is used.
     * 
     * @param principalName The principal name to use for key derivation.
     * @param passPhrase The passphrase to use for key derivation.
     * @return The map of KerberosKey's.
     */
    public static Map<EncryptionType, EncryptionKey> getKerberosKeys( String principalName, String passPhrase ) throws KrbException {
        return getKerberosKeys( principalName, passPhrase, DEFAULT_CIPHERS.keySet() );
    }


    /**
     * Get a list of KerberosKey's for a given principal name and passphrase and list of cipher
     * types to derive keys for.
     *
     * @param principalName The principal name to use for key derivation.
     * @param passPhrase The passphrase to use for key derivation.
     * @param ciphers The set of ciphers to derive keys for.
     * @return The list of KerberosKey's.
     */
    // This will suppress PMD.EmptyCatchBlock warnings in this method
    @SuppressWarnings("PMD.EmptyCatchBlock")
    public static Map<EncryptionType, EncryptionKey> getKerberosKeys( String principalName, String passPhrase,
        Set<EncryptionType> ciphers ) throws KrbException {
        Map<EncryptionType, EncryptionKey> kerberosKeys = new HashMap<EncryptionType, EncryptionKey>();

        for ( EncryptionType encryptionType : ciphers )
        {
            try
            {
                kerberosKeys.put( encryptionType, string2Key( principalName, passPhrase, encryptionType ) );
            }
            catch ( IllegalArgumentException iae )
            {
                // Algorithm AES256 not enabled by policy.
                // Algorithm ArcFourHmac not supported by IBM JREs.
                // Algorithm DESede not supported by IBM JREs.
            }
        }

        return kerberosKeys;
    }


    public static EncryptionKey string2Key( String principalName, String passPhrase, EncryptionType encryptionType ) throws KrbException {
        KerberosPrincipal principal = new KerberosPrincipal( principalName );
        KerberosKey kerberosKey = new KerberosKey( principal, passPhrase.toCharArray(),
                EncryptionUtil.getAlgoNameFromEncType(encryptionType) );
        EncryptionKey ekey = KrbFactory.create(EncryptionKey.class);
        ekey.setKeyType(encryptionType);
        ekey.setKeyData(kerberosKey.getEncoded());
        return ekey;
    }
}
