package org.haox.kerb.server.sam;

import javax.security.auth.kerberos.KerberosKey;

public class TimestampChecker implements KeyIntegrityChecker
{
    private static final long FIVE_MINUTES = 300000;

    // FIXME this whole function seems to be buggy and also I don't find any references to this function in code- kayyagari
    public boolean checkKeyIntegrity( byte[] encryptedData, KerberosKey kerberosKey )
    {
        /*
        EncryptionType keyType = EncryptionType.getTypeByValue( kerberosKey.getKeyType() );
        EncryptionKey key = new EncryptionKey( keyType, kerberosKey.getEncoded() );

        try
        {
            /*
             * Since the pre-auth value is of type PA-ENC-TIMESTAMP, it should be a valid
             * ASN.1 PA-ENC-TS-ENC structure, so we can decode it into EncryptedData.
             *
            EncryptedData sadValue = KerberosDecoder.decodeEncryptedData( encryptedData );

            /*
             * Decrypt the EncryptedData structure to get the PA-ENC-TS-ENC.  Decode the
             * decrypted timestamp into our timestamp object.
             *
            PaEncTsEnc timestamp = ( PaEncTsEnc ) cipherTextHandler.unseal( PAEncTSEnc.class,
                key, sadValue, KeyUsage.NUMBER1 );

            /*
             * Since we got here we must have a valid timestamp structure that we can
             * handle to be within a five minute skew.
             *
            KerberosTime time = timestamp.getPaTimestamp();

            if ( time.isInClockSkew( FIVE_MINUTES ) )
            {
                return true;
            }
        }
        catch ( IOException ioe )
        {
            return false;
        }
        catch ( KerberosException ke )
        {
            return false;
        }
        catch ( ClassCastException cce )
        {
            return false;
        }
        */
        return false;
    }
}
