package org.haox.kerb.codec.kerberos;

import org.haox.kerb.codec.DecodingUtil;
import org.haox.kerb.spec.type.common.EncryptionType;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

public class KerberosEncData {

    public static byte[] decrypt(byte[] data, Key inputKey, EncryptionType etype) throws GeneralSecurityException, IOException {
        Key key = inputKey;
        if (key == null) {
            key = KerberosCredentials.getServerKey(etype);
        }

        Cipher cipher = null;
        byte[] decrypt = null;

        switch (etype) {
        case DES_CBC_MD5:
            try {
                cipher = Cipher.getInstance("DES/CBC/NoPadding");
            } catch(GeneralSecurityException e) {
                throw new GeneralSecurityException("Checksum failed while decrypting.");
            }
            byte[] ivec = new byte[8];
            IvParameterSpec params = new IvParameterSpec(ivec);

            SecretKeySpec skSpec = new SecretKeySpec(key.getEncoded(), "DES");
            SecretKey sk = (SecretKey)skSpec;

            cipher.init(Cipher.DECRYPT_MODE, sk, params);

            byte[] result;
            result = cipher.doFinal(data);

            decrypt = new byte[result.length];
            System.arraycopy(result, 0, decrypt, 0, result.length);

            int tempSize = decrypt.length - 24;

            byte[] output = new byte[tempSize];
            System.arraycopy(decrypt, 24, output, 0, tempSize);

            decrypt = output;
            break;
        case RC4_HMAC:
            byte[] code = DecodingUtil.asBytes(Cipher.DECRYPT_MODE);
            byte[] codeHmac = getHmac(code, key.getEncoded());

            byte[] dataChecksum = new byte[KerberosConstants.CHECKSUM_SIZE];
            System.arraycopy(data, 0, dataChecksum, 0, KerberosConstants.CHECKSUM_SIZE);

            byte[] dataHmac = getHmac(dataChecksum, codeHmac);
            SecretKeySpec dataKey = new SecretKeySpec(dataHmac, KerberosConstants.RC4_ALGORITHM);

            cipher = Cipher.getInstance(KerberosConstants.RC4_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, dataKey);

            int plainDataLength = data.length - KerberosConstants.CHECKSUM_SIZE;
            byte[] plainData = cipher.doFinal(data, KerberosConstants.CHECKSUM_SIZE,
                    plainDataLength);

            byte[] plainDataChecksum = getHmac(plainData, codeHmac);
            if(plainDataChecksum.length >= KerberosConstants.CHECKSUM_SIZE)
                for(int i = 0; i < KerberosConstants.CHECKSUM_SIZE; i++)
                    if(plainDataChecksum[i] != data[i])
                        throw new GeneralSecurityException("Checksum failed while decrypting.");

            int decryptLength = plainData.length - KerberosConstants.CONFOUNDER_SIZE;
            decrypt = new byte[decryptLength];
            System.arraycopy(plainData, KerberosConstants.CONFOUNDER_SIZE, decrypt, 0,
                    decryptLength);
            break;
        default:
            throw new GeneralSecurityException("Unsupported encryption type.");
        }
        return decrypt;
    }

    private static byte[] getHmac(byte[] data, byte[] key) throws GeneralSecurityException {
        Key macKey = new SecretKeySpec(key.clone(), KerberosConstants.HMAC_ALGORITHM);
        Mac mac = Mac.getInstance(KerberosConstants.HMAC_ALGORITHM);
        mac.init(macKey);

        return mac.doFinal(data);
    }
}
