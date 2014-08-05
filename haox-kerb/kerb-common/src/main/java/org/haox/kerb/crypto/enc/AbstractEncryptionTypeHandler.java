package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.AbstractCryptoTypeHandler;
import org.haox.kerb.crypto.EncryptionTypeHandler;
import org.haox.kerb.crypto.cksum.HashProvider;
import org.haox.kerb.crypto.key.KeyMaker;
import org.haox.kerb.spec.KrbException;

public abstract class AbstractEncryptionTypeHandler
        extends AbstractCryptoTypeHandler implements EncryptionTypeHandler {

    private KeyMaker keyMaker;

    public AbstractEncryptionTypeHandler(EncryptProvider encProvider,
          HashProvider hashProvider, KeyMaker keyMaker) {
        super(encProvider, hashProvider);
        this.keyMaker = keyMaker;
    }

    @Override
    public String name() {
        return eType().getName();
    }

    @Override
    public String displayName() {
        return eType().getDisplayName();
    }

    protected int paddingLength(int inputLen) {
        int payloadLen = confounderSize() + checksumSize() + inputLen;
        int padding = paddingSize();

        if (padding == 0 || (payloadLen % padding) == 0) {
            return 0;
        }

        return padding - (payloadLen % padding);
    }

    @Override
    public int confounderSize() {
        return encProvider().blockSize();
    }

    @Override
    public int checksumSize() {
        return hashProvider().hashSize();
    }

    @Override
    public int paddingSize() {
        return encProvider().blockSize();
    }

    @Override
    public int trailerSize() {
        return 0;
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        return keyMaker.str2key(string, salt, param);
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key, int usage) throws KrbException {
        byte[] iv = new byte[encProvider().blockSize()];
        return encrypt(data, key, iv, usage);
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = confounderSize();
        int checksumLen = checksumSize();
        int headerLen = confounderLen + checksumLen;
        int inputLen = data.length;
        int paddingLen = paddingLength(inputLen);
        int trailerLen = trailerSize();

        /**
         *  E(Confounder | Checksum | Plaintext | Padding), or
         *  header | data | padding | trailer, where trailer may be absent
         */

        int workLength = headerLen + inputLen + paddingLen + trailerLen;

        byte[] workBuffer = new byte[workLength];
        System.arraycopy(data, 0, workBuffer, headerLen, data.length);

        int [] workLens = new int[] {confounderLen, checksumLen,
                inputLen, paddingLen, trailerLen};

        encryptWith(workBuffer, workLens, key, iv, usage);
        return workBuffer;
    }

    protected void encryptWith(byte[] workBuffer, int[] workLens,
                          byte[] key, byte[] iv, int usage) throws KrbException {

    }

    public byte[] decrypt(byte[] cipher, byte[] key, int usage)
            throws KrbException {
        byte[] iv = new byte[encProvider().blockSize()];
        return decrypt(cipher, key, iv, usage);
    }

    public byte[] decrypt(byte[] cipher, byte[] key, byte[] iv, int usage)
            throws KrbException {

        int totalLen = cipher.length;
        int confounderLen = confounderSize();
        int checksumLen = checksumSize();
        int trailerLen = trailerSize();
        int dataLen = totalLen - (confounderLen + checksumLen + trailerLen);

        int[] workLens = new int[] {confounderLen, checksumLen, dataLen, trailerLen};
        return decryptWith(cipher, workLens, key, iv, usage);
    }

    protected byte[] decryptWith(byte[] workBuffer, int[] workLens,
                               byte[] key, byte[] iv, int usage) throws KrbException {
        return null;
    }

    public int dataSize(byte[] data)
    // throws Asn1Exception
    {
        // EncodeRef ref = new EncodeRef(data, startOfData());
        // return ref.end - startOfData();
        // should be the above according to spec, but in fact
        // implementations include the pad bytes in the data size
        return data.length - startOfData();
    }

    public int padSize(byte[] data) {
        return data.length - confounderSize() - checksumSize() -
            dataSize(data);
    }

    public int startOfChecksum() {
        return confounderSize();
    }

    public int startOfData() {
        return confounderSize() + checksumSize();
    }

    public int startOfPad(byte[] data) {
        return confounderSize() + checksumSize() + dataSize(data);
    }

    public byte[] decryptedData(byte[] data) {
        int tempSize = dataSize(data);
        byte[] result = new byte[tempSize];
        System.arraycopy(data, startOfData(), result, 0, tempSize);
        return result;
    }
}
