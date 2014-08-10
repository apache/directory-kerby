package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.crypto.key.KeyMaker;
import org.haox.kerb.spec.KrbException;

public abstract class AbstractKeyedCheckSumTypeHandler extends AbstractCheckSumTypeHandler {

    private KeyMaker keyMaker;

    public AbstractKeyedCheckSumTypeHandler(EncryptProvider encProvider, HashProvider hashProvider,
                                            int computeSize, int outputSize) {
        super(encProvider, hashProvider, computeSize, outputSize);
    }

    protected void keyMaker(KeyMaker keyMaker) {
        this.keyMaker = keyMaker;
    }

    protected KeyMaker keyMaker() {
        return keyMaker;
    }

    @Override
    public byte[] makeKeyedChecksum(byte[] data,
                                    byte[] key, int usage) throws KrbException {
        return makeKeyedChecksum(data, 0, data.length, key, usage);
    }

    @Override
    public byte[] makeKeyedChecksum(byte[] data, int start, int len,
                                    byte[] key, int usage) throws KrbException {
        int computeSize = computeSize();
        int outputSize = outputSize();

        int[] workLens = new int[] {computeSize, outputSize};
        byte[] workBuffer = new byte[computeSize];
        makeKeyedChecksumWith(workBuffer, workLens, data, start, len, key, usage);

        if (outputSize < computeSize) {
            byte[] output = new byte[outputSize];
            System.arraycopy(workBuffer, 0, output, 0, outputSize);
            return output;
        }
        return workBuffer;
    }

    protected void makeKeyedChecksumWith(byte[] workBuffer, int[] workLens, byte[] data,
                                         int start, int len, byte[] key, int usage) throws KrbException {

    }

    @Override
    public boolean verifyKeyedChecksum(byte[] data, byte[] key,
                                       int usage, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }
}
