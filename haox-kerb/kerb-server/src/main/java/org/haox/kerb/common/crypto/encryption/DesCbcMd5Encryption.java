package org.haox.kerb.common.crypto.encryption;

import org.apache.directory.api.ldap.model.constants.Loggers;
import org.apache.directory.shared.kerberos.exceptions.ErrorType;
import org.apache.directory.shared.kerberos.exceptions.KerberosException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

class DesCbcMd5Encryption extends EncryptionEngine
{
    /** The loggers for this class */
    private static final Logger LOG_KRB = LoggerFactory.getLogger( Loggers.KERBEROS_LOG.getName() );

    private static final byte[] iv = new byte[]
        { ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00,
            ( byte ) 0x00 };


    public EncryptionType getEncryptionType()
    {
        return EncryptionType.DES_CBC_MD5;
    }


    public int getConfounderLength()
    {
        return 8;
    }


    public int getChecksumLength()
    {
        return 16;
    }


    public byte[] calculateIntegrity( byte[] data, byte[] key, KeyUsage usage )
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


    public byte[] getDecryptedData( EncryptionKey key, EncryptedData data, KeyUsage usage ) throws KrbException {
        LOG_KRB.debug( "Decrypting data using {}", key );

        // decrypt the data
        byte[] decryptedData = decrypt( data.getCipher(), key.getKeyData() );

        // extract the old checksum
        byte[] oldChecksum = new byte[getChecksumLength()];
        System.arraycopy( decryptedData, getConfounderLength(), oldChecksum, 0, oldChecksum.length );

        // zero out the old checksum in the cipher text
        for ( int i = getConfounderLength(); i < getConfounderLength() + getChecksumLength(); i++ )
        {
            decryptedData[i] = 0;
        }

        // calculate a new checksum
        byte[] newChecksum = calculateIntegrity( decryptedData, key.getKeyData(), usage );

        // compare checksums
        if ( !Arrays.equals( oldChecksum, newChecksum ) )
        {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY );
        }

        // remove leading confounder and checksum
        return removeLeadingBytes( decryptedData, getConfounderLength(), getChecksumLength() );
    }


    public EncryptedData getEncryptedData( EncryptionKey key, byte[] plainText, KeyUsage usage ) throws KrbException {
        // build the ciphertext structure
        byte[] conFounder = getRandomBytes( getConfounderLength() );
        byte[] zeroedChecksum = new byte[getChecksumLength()];
        byte[] dataBytes = concatenateBytes( conFounder, concatenateBytes( zeroedChecksum, plainText ) );
        byte[] paddedDataBytes = padString( dataBytes );
        byte[] checksumBytes = calculateIntegrity( paddedDataBytes, null, usage );

        // lay the checksum into the ciphertext
        for ( int i = getConfounderLength(); i < getConfounderLength() + getChecksumLength(); i++ )
        {
            paddedDataBytes[i] = checksumBytes[i - getConfounderLength()];
        }

        byte[] encryptedData = encrypt( paddedDataBytes, key.getKeyData() );
        return makeEncryptedData(encryptedData);
    }


    public byte[] encrypt( byte[] plainText, byte[] keyBytes )
    {
        return processCipher( true, plainText, keyBytes );
    }


    public byte[] decrypt( byte[] cipherText, byte[] keyBytes )
    {
        return processCipher( false, cipherText, keyBytes );
    }


    private byte[] processCipher( boolean isEncrypt, byte[] data, byte[] keyBytes )
    {
        try
        {
            Cipher cipher = Cipher.getInstance( "DES/CBC/NoPadding" );
            SecretKey key = new SecretKeySpec( keyBytes, "DES" );

            AlgorithmParameterSpec paramSpec = new IvParameterSpec( iv );

            if ( isEncrypt )
            {
                cipher.init( Cipher.ENCRYPT_MODE, key, paramSpec );
            }
            else
            {
                cipher.init( Cipher.DECRYPT_MODE, key, paramSpec );
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
