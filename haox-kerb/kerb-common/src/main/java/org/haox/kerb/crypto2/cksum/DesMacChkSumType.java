package org.haox.kerb.crypto2.cksum;

import org.haox.kerb.common.Checksum;
import org.haox.kerb.common.Confounder;
import org.haox.kerb.crypto2.AbstractChkSumType;
import org.haox.kerb.crypto2.Des;
import org.haox.kerb.spec.KrbException;

import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;

public class DesMacChkSumType extends AbstractChkSumType {

    public DesMacChkSumType() {
    }

    public int confounderSize() {
        return 8;
    }

    public int cksumType() {
        return Checksum.CKSUMTYPE_DES_MAC;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 16;
    }

    public int keySize() {
        return 8;
    }

    public byte[] calculateChecksum(byte[] data, int size) {
        return null;
    }

    /**
     * Calculates keyed checksum.
     * @param data the data used to generate the checksum.
     * @param size length of the data.
     * @param key the key used to encrypt the checksum.
     * @return keyed checksum.
     *
     * @modified by Yanni Zhang, 12/08/99.
     */
    public byte[] calculateKeyedChecksum(byte[] data, int size, byte[] key,
        int usage) throws KrbException {
        byte[] new_data = new byte[size + confounderSize()];
        byte[] conf = Confounder.bytes(confounderSize());
        System.arraycopy(conf, 0, new_data, 0, confounderSize());
        System.arraycopy(data, 0, new_data, confounderSize(), size);

        //check for weak keys
        try {
            if (DESKeySpec.isWeak(key, 0)) {
                key[7] = (byte)(key[7] ^ 0xF0);
            }
        } catch (InvalidKeyException ex) {
            // swallow, since it should never happen
        }
        byte[] residue_ivec = new byte[key.length];
        byte[] residue = Des.des_cksum(residue_ivec, new_data, key);
        byte[] cksum = new byte[cksumSize()];
        System.arraycopy(conf, 0, cksum, 0, confounderSize());
        System.arraycopy(residue, 0, cksum, confounderSize(),
                         cksumSize() - confounderSize());

        byte[] new_key = new byte[keySize()];
        System.arraycopy(key, 0, new_key, 0, key.length);
        for (int i = 0; i < new_key.length; i++)
        new_key[i] = (byte)(new_key[i] ^ 0xf0);
        //check for weak keys
        try {
            if (DESKeySpec.isWeak(new_key, 0)) {
                new_key[7] = (byte)(new_key[7] ^ 0xF0);
            }
        } catch (InvalidKeyException ex) {
            // swallow, since it should never happen
        }
        byte[] ivec = new byte[new_key.length];

        //des-cbc encrypt
        byte[] enc_cksum = new byte[cksum.length];
        Des.cbc_encrypt(cksum, enc_cksum, new_key, ivec, true);
        return enc_cksum;
    }

    /**
     * Verifies keyed checksum.
     * @param data the data.
     * @param size the length of data.
     * @param key the key used to encrypt the checksum.
     * @param checksum
     * @return true if verification is successful.
     *
     * @modified by Yanni Zhang, 12/08/99.
     */
    public boolean verifyKeyedChecksum(byte[] data, int size,
        byte[] key, byte[] checksum, int usage) throws KrbException {
        byte[] cksum = decryptKeyedChecksum(checksum, key);

        byte[] new_data = new byte[size + confounderSize()];
        System.arraycopy(cksum, 0, new_data, 0, confounderSize());
        System.arraycopy(data, 0, new_data, confounderSize(), size);

        //check for weak keys
        try {
            if (DESKeySpec.isWeak(key, 0)) {
                key[7] = (byte)(key[7] ^ 0xF0);
            }
        } catch (InvalidKeyException ex) {
            // swallow, since it should never happen
        }
        byte[] ivec = new byte[key.length];
        byte[] new_cksum = Des.des_cksum(ivec, new_data, key);
        byte[] orig_cksum = new byte[cksumSize() - confounderSize()];
        System.arraycopy(cksum,  confounderSize(), orig_cksum, 0,
                         cksumSize() - confounderSize());
        return isChecksumEqual(orig_cksum, new_cksum);
    }

    /**
     * Decrypts keyed checksum.
     * @param enc_cksum the buffer for encrypted checksum.
     * @param key the key.
     * @return the checksum.
     *
     * @modified by Yanni Zhang, 12/08/99.
     */
    private byte[] decryptKeyedChecksum(byte[] enc_cksum, byte[] key) throws KrbException {
        byte[] new_key = new byte[keySize()];
        System.arraycopy(key, 0, new_key, 0, key.length);
        for (int i = 0; i < new_key.length; i++)
        new_key[i] = (byte)(new_key[i] ^ 0xf0);
        //check for weak keys
        try {
            if (DESKeySpec.isWeak(new_key, 0)) {
                new_key[7] = (byte)(new_key[7] ^ 0xF0);
            }
        } catch (InvalidKeyException ex) {
            // swallow, since it should never happen
        }
        byte[] ivec = new byte[new_key.length];
        byte[] cksum = new byte[enc_cksum.length];
        Des.cbc_encrypt(enc_cksum, cksum, new_key, ivec, false);
        return cksum;
    }

}
