package org.haox.kerb.common.crypto.checksum;

import org.haox.kerb.common.crypto.encryption.KeyUsage;
import org.haox.kerb.spec.type.common.ChecksumType;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class RsaMd5Checksum implements ChecksumEngine
{
    public ChecksumType checksumType()
    {
        return ChecksumType.RSA_MD5;
    }


    public byte[] calculateChecksum( byte[] data, byte[] key, KeyUsage usage )
    {
        try
        {
            MessageDigest digester = MessageDigest.getInstance("MD5");
            return digester.digest( data );
        }
        catch ( NoSuchAlgorithmException nsae )
        {
            return null;
        }
    }
}
