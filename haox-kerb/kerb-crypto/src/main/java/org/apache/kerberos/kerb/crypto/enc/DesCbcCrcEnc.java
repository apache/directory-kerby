package org.apache.kerberos.kerb.crypto.enc;

import org.apache.kerberos.kerb.crypto.cksum.provider.Crc32Provider;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.common.CheckSumType;
import org.apache.kerberos.kerb.spec.common.EncryptionType;

public class DesCbcCrcEnc extends DesCbcEnc {

    public DesCbcCrcEnc() {
        super(new Crc32Provider());
    }

    public EncryptionType eType() {
        return EncryptionType.DES_CBC_CRC;
    }

    public CheckSumType checksumType() {
        return CheckSumType.CRC32;
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key, int usage) throws KrbException {
        byte[] iv = new byte[encProvider().blockSize()];
        System.arraycopy(key, 0, iv, 0, key.length);
        return encrypt(data, key, iv, usage);
    }

    @Override
    public byte[] decrypt(byte[] cipher, byte[] key, int usage)
            throws KrbException {
        byte[] iv = new byte[encProvider().blockSize()];
        System.arraycopy(key, 0, iv, 0, key.length);
        return decrypt(cipher, key, iv, usage);
    }
}
