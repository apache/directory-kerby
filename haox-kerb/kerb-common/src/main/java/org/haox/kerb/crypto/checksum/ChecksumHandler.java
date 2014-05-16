package org.haox.kerb.crypto.checksum;

import org.haox.kerb.crypto.encryption.Aes128CtsSha1Encryption;
import org.haox.kerb.crypto.encryption.Aes256CtsSha1Encryption;
import org.haox.kerb.crypto.encryption.Des3CbcSha1KdEncryption;
import org.haox.kerb.crypto.encryption.KeyUsage;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.Checksum;
import org.haox.kerb.spec.type.common.ChecksumType;
import org.haox.kerb.spec.type.common.KrbErrorCode;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * A Hashed Adapter encapsulating checksum engines for performing integrity checks.
 */
public class ChecksumHandler
{
    /** A map of the default encodable class names to the encoder class names. */
    private static final Map<ChecksumType, Class<? extends ChecksumEngine>> DEFAULT_CHECKSUMS;

    static {
        Map<ChecksumType, Class<? extends ChecksumEngine>> map = new HashMap<ChecksumType, Class<? extends ChecksumEngine>>();

        map.put( ChecksumType.HMAC_MD5_ARCFOUR, HmacMd5Checksum.class );
        map.put( ChecksumType.HMAC_SHA1_96_AES128, Aes128CtsSha1Encryption.class );
        map.put( ChecksumType.HMAC_SHA1_96_AES256, Aes256CtsSha1Encryption.class );
        map.put( ChecksumType.HMAC_SHA1_DES3, Des3CbcSha1KdEncryption.class );
        map.put( ChecksumType.RSA_MD5, RsaMd5Checksum.class );

        DEFAULT_CHECKSUMS = Collections.unmodifiableMap( map );
    }

    public Checksum checksum(ChecksumType checksumType,
                             byte[] bytes, byte[] key, KeyUsage usage) throws KrbException {
        if ( !DEFAULT_CHECKSUMS.containsKey( checksumType ) )
        {
            throw new KrbException(KrbErrorCode.KDC_ERR_SUMTYPE_NOSUPP );
        }

        ChecksumEngine digester = getEngine( checksumType );
        byte[] checksumBytes = digester.calculateChecksum(bytes, key, usage);
        Checksum checksum = new Checksum();
        checksum.setCksumtype(checksumType);
        checksum.setChecksum(checksumBytes);
        return checksum;
    }

    public void verifyChecksum( Checksum checksum, byte[] bytes, byte[] key, KeyUsage usage ) throws KrbException {
        if ( checksum == null ) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_INAPP_CKSUM );
        }

        if ( !DEFAULT_CHECKSUMS.containsKey( checksum.getCksumtype() ) ) {
            throw new KrbException(KrbErrorCode.KDC_ERR_SUMTYPE_NOSUPP );
        }

        ChecksumType checksumType = checksum.getCksumtype();
        Checksum newChecksum = checksum(checksumType, bytes, key, usage);

        if ( !newChecksum.equals( checksum ) ) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_MODIFIED );
        }
    }

    private ChecksumEngine getEngine( ChecksumType checksumType ) throws KrbException
    {
        Class<?> clazz = DEFAULT_CHECKSUMS.get( checksumType );

        if ( clazz == null ) {
            throw new KrbException(KrbErrorCode.KDC_ERR_SUMTYPE_NOSUPP );
        }

        try {
            return (ChecksumEngine) clazz.newInstance();
        }
        catch ( IllegalAccessException iae ) {
            throw new KrbException(KrbErrorCode.KDC_ERR_SUMTYPE_NOSUPP, iae );
        } catch ( InstantiationException ie ) {
            throw new KrbException(KrbErrorCode.KDC_ERR_SUMTYPE_NOSUPP, ie );
        }
    }
}
