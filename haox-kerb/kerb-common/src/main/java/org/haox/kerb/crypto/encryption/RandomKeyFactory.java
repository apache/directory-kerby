package org.haox.kerb.crypto.encryption;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbErrorCode;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;


/**
 * A factory class for producing random keys, suitable for use as session keys.  For a
 * list of desired cipher types, Kerberos random-to-key functions are used to derive
 * keys for DES-, DES3-, AES-, and RC4-based encryption types.
 */
public class RandomKeyFactory
{
    /** A map of default encryption types mapped to cipher names. */
    private static final Map<EncryptionType, String> DEFAULT_CIPHERS;

    static
    {
        Map<EncryptionType, String> map = new HashMap<EncryptionType, String>();

        map.put( EncryptionType.DES_CBC_MD5, "DES" );
        map.put( EncryptionType.DES3_CBC_SHA1_KD, "DESede" );
        map.put( EncryptionType.RC4_HMAC, "RC4" );
        map.put( EncryptionType.AES128_CTS_HMAC_SHA1_96, "AES" );
        map.put( EncryptionType.AES256_CTS_HMAC_SHA1_96, "AES" );

        DEFAULT_CIPHERS = Collections.unmodifiableMap( map );
    }

    public static Map<EncryptionType, EncryptionKey> getRandomKeys() throws KrbException {
        return getRandomKeys( DEFAULT_CIPHERS.keySet() );
    }

    public static Map<EncryptionType, EncryptionKey> getRandomKeys( Set<EncryptionType> ciphers )
            throws KrbException {
        Map<EncryptionType, EncryptionKey> map = new HashMap<EncryptionType, EncryptionKey>();

        for ( EncryptionType encryptionType : ciphers )
        {
            map.put( encryptionType, getRandomKey( encryptionType ) );
        }

        return map;
    }

    public static EncryptionKey getRandomKey( EncryptionType encryptionType ) throws KrbException {
        String algorithm = DEFAULT_CIPHERS.get( encryptionType );

        if ( algorithm == null )
        {
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP);
        }

        try
        {
            KeyGenerator keyGenerator = KeyGenerator.getInstance( algorithm );

            if ( encryptionType.equals( EncryptionType.AES128_CTS_HMAC_SHA1_96 ) )
            {
                keyGenerator.init( 128 );
            }

            if ( encryptionType.equals( EncryptionType.AES256_CTS_HMAC_SHA1_96 ) )
            {
                keyGenerator.init( 256 );
            }

            SecretKey key = keyGenerator.generateKey();

            byte[] keyBytes = key.getEncoded();

            return EncryptionUtil.createEncryptionKey(encryptionType, keyBytes);
        }
        catch ( NoSuchAlgorithmException nsae )
        {
            throw new KrbException( KrbErrorCode.KDC_ERR_ETYPE_NOSUPP, nsae );
        }
    }
}
