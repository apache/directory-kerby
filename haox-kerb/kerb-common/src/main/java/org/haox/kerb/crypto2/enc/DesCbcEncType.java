package org.haox.kerb.crypto2.enc;

import org.haox.kerb.common.Confounder;
import org.haox.kerb.crypto2.AbstractEncType;
import org.haox.kerb.crypto2.Des;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbErrorCode;

abstract class DesCbcEncType extends AbstractEncType {
    protected abstract byte[] calculateChecksum(byte[] data, int size)
        throws KrbException;

    public int blockSize() {
        return 8;
    }

    public int keySize() {
        return 8;
    }

    /**
     * Encrypts the data using DES in CBC mode.
     * @param data the buffer for plain text.
     * @param key the key to encrypt the data.
     * @return the buffer for encrypted data.
     *
     * @written by Yanni Zhang, Dec 6 99.
     */

    public byte[] encrypt(byte[] data, byte[] key, int usage)
         throws KrbException {
        byte[] ivec = new byte[keySize()];
        return encrypt(data, key, ivec, usage);
    }

    /**
     * Encrypts the data using DES in CBC mode.
     * @param data the buffer for plain text.
     * @param key the key to encrypt the data.
     * @param ivec initialization vector.
     * @return buffer for encrypted data.
     *
     * @modified by Yanni Zhang, Feb 24 00.
     */
    public byte[] encrypt(byte[] data, byte[] key, byte[] ivec,
        int usage) throws KrbException {

        /*
         * To meet export control requirements, double check that the
         * key being used is no longer than 64 bits.
         *
         * Note that from a protocol point of view, an
         * algorithm that is not DES will be rejected before this
         * point. Also, a  DES key that is not 64 bits will be
         * rejected by a good implementations of JCE.
         */
        if (key.length > 8)
        throw new KrbException("Invalid DES Key!");

        int new_size = data.length + confounderSize() + checksumSize();
        byte[] new_data;
        byte pad;
        /*Data padding: using Kerberos 5 GSS-API mechanism (1.2.2.3), Jun 1996.
         *Before encryption, plaintext data is padded to the next higest multiple of blocksize.
         *by appending between 1 and 8 bytes, the value of each such byte being the total number
         *of pad bytes. For example, if new_size = 10, blockSize is 8, we should pad 2 bytes,
         *and the value of each byte is 2.
         *If plaintext data is a multiple of blocksize, we pad a 8 bytes of 8.
         */
        if (new_size % blockSize() == 0) {
            new_data = new byte[new_size + blockSize()];
            pad = (byte)8;
        }
        else {
            new_data = new byte[new_size + blockSize() - new_size % blockSize()];
            pad = (byte)(blockSize() - new_size % blockSize());
        }
        for (int i = new_size; i < new_data.length; i++) {
            new_data[i] = pad;
        }
        byte[] conf = Confounder.bytes(confounderSize());
        System.arraycopy(conf, 0, new_data, 0, confounderSize());
        System.arraycopy(data, 0, new_data, startOfData(), data.length);
        byte[] cksum = calculateChecksum(new_data, new_data.length);
        System.arraycopy(cksum, 0, new_data, startOfChecksum(),
                         checksumSize());
        byte[] cipher = new byte[new_data.length];
        Des.cbc_encrypt(new_data, cipher, key, ivec, true);
        return cipher;
    }

    /**
     * Decrypts the data using DES in CBC mode.
     * @param cipher the input buffer.
     * @param key the key to decrypt the data.
     *
     * @written by Yanni Zhang, Dec 6 99.
     */
    public byte[] decrypt(byte[] cipher, byte[] key, int usage)
        throws KrbException {
        byte[] ivec = new byte[keySize()];
        return decrypt(cipher, key, ivec, usage);
    }

    /**
     * Decrypts the data using DES in CBC mode.
     * @param cipher the input buffer.
     * @param key the key to decrypt the data.
     * @param ivec initialization vector.
     *
     * @modified by Yanni Zhang, Dec 6 99.
     */
    public byte[] decrypt(byte[] cipher, byte[] key, byte[] ivec, int usage)
        throws KrbException {

        /*
         * To meet export control requirements, double check that the
         * key being used is no longer than 64 bits.
         *
         * Note that from a protocol point of view, an
         * algorithm that is not DES will be rejected before this
         * point. Also, a DES key that is not 64 bits will be
         * rejected by a good JCE provider.
         */
        if (key.length > 8)
            throw new KrbException("Invalid DES Key!");

        byte[] data = new byte[cipher.length];
        Des.cbc_encrypt(cipher, data, key, ivec, false);
        if (!isChecksumValid(data))
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY);
        return data;
    }

    private void copyChecksumField(byte[] data, byte[] cksum) {
        for (int i = 0; i < checksumSize();  i++)
            data[startOfChecksum() + i] = cksum[i];
    }

    private byte[] checksumField(byte[] data) {
        byte[] result = new byte[checksumSize()];
        for (int i = 0; i < checksumSize(); i++)
        result[i] = data[startOfChecksum() + i];
        return result;
    }

    private void resetChecksumField(byte[] data) {
        for (int i = startOfChecksum(); i < startOfChecksum() +
                 checksumSize();  i++)
            data[i] = 0;
    }

    /*
        // Not used.
    public void setChecksum(byte[] data, int size) throws KrbCryptoException{
        resetChecksumField(data);
        byte[] cksum = calculateChecksum(data, size);
        copyChecksumField(data, cksum);
    }
*/

    private byte[] generateChecksum(byte[] data) throws KrbException{
        byte[] cksum1 = checksumField(data);
        resetChecksumField(data);
        byte[] cksum2 = calculateChecksum(data, data.length);
        copyChecksumField(data, cksum1);
        return cksum2;
    }

    private boolean isChecksumEqual(byte[] cksum1, byte[] cksum2) {
        if (cksum1 == cksum2)
            return true;
        if ((cksum1 == null && cksum2 != null) ||
            (cksum1 != null && cksum2 == null))
            return false;
        if (cksum1.length != cksum2.length)
            return false;
        for (int i = 0; i < cksum1.length; i++)
            if (cksum1[i] != cksum2[i])
                return false;
        return true;
    }

    protected boolean isChecksumValid(byte[] data) throws KrbException {
        byte[] cksum1 = checksumField(data);
        byte[] cksum2 = generateChecksum(data);
        return isChecksumEqual(cksum1, cksum2);
    }
}
