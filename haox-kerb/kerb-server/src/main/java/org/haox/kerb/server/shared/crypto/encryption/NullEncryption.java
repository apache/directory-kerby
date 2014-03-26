package org.haox.kerb.server.shared.crypto.encryption;

import org.apache.directory.shared.kerberos.exceptions.KerberosException;
import org.haox.kerb.server.shared.crypto.KeyUsage;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

class NullEncryption extends EncryptionEngine
{
    public EncryptionType getEncryptionType()
    {
        return EncryptionType.NULL;
    }


    public int getChecksumLength()
    {
        return 0;
    }


    public int getConfounderLength()
    {
        return 0;
    }


    public byte[] getDecryptedData( EncryptionKey key, EncryptedData data, KeyUsage usage ) throws KerberosException, KrbException {
        return data.getCipher();
    }


    public EncryptedData getEncryptedData( EncryptionKey key, byte[] plainText, KeyUsage usage ) throws KrbException {
        return makeEncryptedData(plainText);
    }


    public byte[] encrypt( byte[] plainText, byte[] keyBytes )
    {
        return plainText;
    }


    public byte[] decrypt( byte[] cipherText, byte[] keyBytes )
    {
        return cipherText;
    }


    public byte[] calculateIntegrity( byte[] plainText, byte[] key, KeyUsage usage )
    {
        return null;
    }
}
