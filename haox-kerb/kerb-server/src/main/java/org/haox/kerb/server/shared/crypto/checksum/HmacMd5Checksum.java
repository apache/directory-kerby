package org.haox.kerb.server.shared.crypto.checksum;

import org.haox.kerb.server.shared.crypto.KeyUsage;
import org.haox.kerb.spec.type.common.ChecksumType;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

class HmacMd5Checksum implements ChecksumEngine
{
    public ChecksumType checksumType()
    {
        return ChecksumType.HMAC_MD5_ARCFOUR;
    }


    public byte[] calculateChecksum( byte[] data, byte[] key, KeyUsage usage )
    {
        try
        {
            SecretKey sk = new SecretKeySpec( key, "ARCFOUR" );

            Mac mac = Mac.getInstance( "HmacMD5" );
            mac.init( sk );

            return mac.doFinal( data );
        }
        catch ( GeneralSecurityException nsae )
        {
            nsae.printStackTrace();
            return null;
        }
    }
}
