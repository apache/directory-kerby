package org.haox.kerb.crypto.checksum;

import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.type.common.CheckSumType;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class RsaMd5Checksum implements ChecksumEngine
{
    public CheckSumType checksumType()
    {
        return CheckSumType.RSA_MD5;
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
