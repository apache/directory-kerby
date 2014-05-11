package org.haox.kerb.common.crypto.encryption;

import org.apache.directory.shared.kerberos.exceptions.KerberosException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

class ArcFourHmacMd5Encryption extends EncryptionEngine
{
    public EncryptionType getEncryptionType()
    {
        return EncryptionType.RC4_HMAC;
    }


    public int getChecksumLength()
    {
        return 16;
    }


    public int getConfounderLength()
    {
        return 8;
    }


    public byte[] getDecryptedData( EncryptionKey key, EncryptedData data, KeyUsage usage ) throws KrbException {
        return data.getCipher();
    }


    public EncryptedData getEncryptedData( EncryptionKey key, byte[] plainText, KeyUsage usage ) throws KrbException {
        return makeEncryptedData(plainText);
    }


    public byte[] encrypt( byte[] plainText, byte[] keyBytes )
    {
        return processCipher( true, plainText, keyBytes );
    }


    public byte[] decrypt( byte[] cipherText, byte[] keyBytes )
    {
        return processCipher( false, cipherText, keyBytes );
    }


    public byte[] calculateIntegrity( byte[] data, byte[] key, KeyUsage usage )
    {
        try
        {
            Mac digester = Mac.getInstance( "HmacMD5" );
            return digester.doFinal( data );
        }
        catch ( NoSuchAlgorithmException nsae )
        {
            return null;
        }
    }


    private byte[] processCipher( boolean isEncrypt, byte[] data, byte[] keyBytes )
    {
        try
        {
            Cipher cipher = Cipher.getInstance( "ARCFOUR" );
            SecretKey key = new SecretKeySpec( keyBytes, "ARCFOUR" );

            if ( isEncrypt )
            {
                cipher.init( Cipher.ENCRYPT_MODE, key );
            }
            else
            {
                cipher.init( Cipher.DECRYPT_MODE, key );
            }

            return cipher.doFinal( data );
        }
        catch ( GeneralSecurityException nsae )
        {
            nsae.printStackTrace();
            return null;
        }
    }
}
