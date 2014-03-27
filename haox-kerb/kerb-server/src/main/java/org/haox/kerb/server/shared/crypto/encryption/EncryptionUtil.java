package org.haox.kerb.server.shared.crypto.encryption;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbFactory;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

import java.util.*;

import static org.haox.kerb.spec.type.common.EncryptionType.*;

public class EncryptionUtil
{
    /**
     * an order preserved map containing cipher names to the corresponding algorithm
     * names in the descending order of strength
     */
    private static final Map<String, String> cipherAlgoMap = new LinkedHashMap<String, String>();

    private static final Set<EncryptionType> oldEncTypes = new HashSet<EncryptionType>();

    static {
        cipherAlgoMap.put( "rc4", "ArcFourHmac" );
        cipherAlgoMap.put( "aes256", "AES256" );
        cipherAlgoMap.put( "aes128", "AES128" );
        cipherAlgoMap.put( "des3", "DESede" );
        cipherAlgoMap.put( "des", "DES" );

        oldEncTypes.add( DES_CBC_CRC );
        oldEncTypes.add( DES_CBC_MD4 );
        oldEncTypes.add( DES_CBC_MD5 );
        oldEncTypes.add( DES_EDE3_CBC_ENV_OID );
        oldEncTypes.add( DES3_CBC_MD5 );
        oldEncTypes.add( DES3_CBC_SHA1 );
        oldEncTypes.add( DES3_CBC_SHA1_KD );
        oldEncTypes.add( DSAWITHSHA1_CMSOID );
        oldEncTypes.add( MD5WITHRSAENCRYPTION_CMSOID );
        oldEncTypes.add( SHA1WITHRSAENCRYPTION_CMSOID );
        oldEncTypes.add( RC2CBC_ENVOID );
        oldEncTypes.add( RSAENCRYPTION_ENVOID );
        oldEncTypes.add( RSAES_OAEP_ENV_OID );
        oldEncTypes.add( RC4_HMAC );
    }

    /**
     * Get the matching encryption type from the configured types, searching
     * into the requested types. We returns the first we find.
     *
     * @param requestedTypes The client encryption types
     * @param configuredTypes The configured encryption types
     * @return The first matching encryption type.
     */
    public static EncryptionType getBestEncryptionType( Set<EncryptionType> requestedTypes,
        Set<EncryptionType> configuredTypes )
    {
        for ( EncryptionType encryptionType : configuredTypes )
        {
            if ( requestedTypes.contains( encryptionType ) )
            {
                return encryptionType;
            }
        }

        return null;
    }


    /**
     * Build a list of encryptionTypes
     *
     * @param encryptionTypes The encryptionTypes
     * @return A list comma separated of the encryptionTypes
     */
    public static String getEncryptionTypesString( Set<EncryptionType> encryptionTypes )
    {
        StringBuilder sb = new StringBuilder();
        boolean isFirst = true;

        for ( EncryptionType etype : encryptionTypes )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                sb.append( ", " );
            }

            sb.append( etype );
        }

        return sb.toString();
    }

    public static String getAlgoNameFromEncType( EncryptionType encType )
    {
        String cipherName = encType.name().toLowerCase();

        for ( String c : cipherAlgoMap.keySet() )
        {
            if ( cipherName.startsWith( c ) )
            {
                return cipherAlgoMap.get( c );
            }
        }

        throw new IllegalArgumentException( "Unknown algorithm name for the encryption type " + encType );
    }


    /**
     * Order a list of EncryptionType in a decreasing strength order
     *
     * @param etypes The ETypes to order
     * @return A list of ordered ETypes. he strongest is on the left.
     */
    public static Set<EncryptionType> orderEtypesByStrength( Set<EncryptionType> etypes )
    {
        Set<EncryptionType> ordered = new LinkedHashSet<EncryptionType>( etypes.size() );

        for ( String algo : cipherAlgoMap.values() )
        {
            for ( EncryptionType encType : etypes )
            {
                String foundAlgo = getAlgoNameFromEncType( encType );

                if ( algo.equals( foundAlgo ) )
                {
                    ordered.add( encType );
                }
            }
        }

        return ordered;
    }

    /**
     * checks if the given encryption type is *new* (ref sec#3.1.3 of rfc4120)
     *
     * @param eType the encryption type
     * @return true if the encryption type is new, false otherwise
     */
    public static boolean isNewEncryptionType( EncryptionType eType )
    {
        return !oldEncTypes.contains( eType );
    }

    public static EncryptionKey createEncryptionKey(EncryptionType type, byte[] keyData) throws KrbException {
        EncryptionKey ekey = KrbFactory.create(EncryptionKey.class);
        ekey.setKeyType(type);
        ekey.setKeyData(keyData);

        return ekey;
    }

}
