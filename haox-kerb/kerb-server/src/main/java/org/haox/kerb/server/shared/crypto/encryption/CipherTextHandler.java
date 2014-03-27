package org.haox.kerb.server.shared.crypto.encryption;

import org.apache.directory.api.asn1.AbstractAsn1Object;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.ldap.model.constants.Loggers;
import org.apache.directory.shared.kerberos.exceptions.ErrorType;
import org.apache.directory.shared.kerberos.exceptions.KerberosException;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.server.shared.crypto.KeyUsage;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


/**
 * A Hashed Adapter encapsulating ASN.1 cipher text engines to
 * perform encrypt() and decrypt() operations.
 */
public class CipherTextHandler
{
    /** The loggers for this class */
    private static final Logger LOG_KRB = LoggerFactory.getLogger( Loggers.KERBEROS_LOG.getName() );

    /** a map of the default encryption types to the encryption engine class names */
    private static final Map<EncryptionType, Class<? extends EncryptionEngine>> DEFAULT_CIPHERS;

    // Initialize the list of encyption mechanisms
    static {
        Map<EncryptionType, Class<? extends EncryptionEngine>> map = new HashMap<EncryptionType, Class<? extends EncryptionEngine>>();

        map.put( EncryptionType.DES_CBC_MD5, DesCbcMd5Encryption.class );
        map.put( EncryptionType.DES3_CBC_SHA1_KD, Des3CbcSha1KdEncryption.class );
        map.put( EncryptionType.AES128_CTS_HMAC_SHA1_96, Aes128CtsSha1Encryption.class );
        map.put( EncryptionType.AES256_CTS_HMAC_SHA1_96, Aes256CtsSha1Encryption.class );
        map.put( EncryptionType.RC4_HMAC, ArcFourHmacMd5Encryption.class );

        DEFAULT_CIPHERS = Collections.unmodifiableMap( map );
    }


    /**
     * Performs an encode and an encrypt.
     *
     * @param key The key to use for encrypting.
     * @param usage The key usage.
     * @return The Kerberos EncryptedData.
     * @throws org.apache.directory.shared.kerberos.exceptions.KerberosException
     */
    public EncryptedData seal( EncryptionKey key, KrbType message, KeyUsage usage ) throws KerberosException, KrbException {
        try
        {
            byte[] encoded = KrbCodec.encode(message);
            return encrypt( key, encoded, usage );
        } catch ( ClassCastException cce )
        {
            throw new KerberosException( ErrorType.KRB_AP_ERR_BAD_INTEGRITY, cce );
        }
    }


    public EncryptedData encrypt( EncryptionKey key, byte[] plainText, KeyUsage usage ) throws KerberosException, KrbException {
        EncryptionEngine engine = getEngine( key );

        return engine.getEncryptedData( key, plainText, usage );
    }


    /**
     * Decrypt a block of data.
     *
     * @param key The key used to decrypt the data
     * @param data The data to decrypt
     * @param usage The key usage number
     * @return The decrypted data as a byte[]
     * @throws org.apache.directory.shared.kerberos.exceptions.KerberosException If the decoding failed
     */
    public byte[] decrypt( EncryptionKey key, EncryptedData data, KeyUsage usage ) throws KerberosException, KrbException {
        LOG_KRB.debug( "Decrypting data using key {} and usage {}", key.getKeyType(), usage );
        EncryptionEngine engine = getEngine( key );

        return engine.getDecryptedData( key, data, usage );
    }


    private EncryptionEngine getEngine( EncryptionKey key ) throws KerberosException, KrbException {
        EncryptionType encryptionType = key.getKeyType();

        Class<?> clazz = DEFAULT_CIPHERS.get( encryptionType );

        if ( clazz == null )
        {
            throw new KerberosException( ErrorType.KDC_ERR_ETYPE_NOSUPP );
        }

        try
        {
            return (EncryptionEngine) clazz.newInstance();
        }
        catch ( IllegalAccessException iae )
        {
            throw new KerberosException( ErrorType.KDC_ERR_ETYPE_NOSUPP, iae );
        }
        catch ( InstantiationException ie )
        {
            throw new KerberosException( ErrorType.KDC_ERR_ETYPE_NOSUPP, ie );
        }
    }
}
