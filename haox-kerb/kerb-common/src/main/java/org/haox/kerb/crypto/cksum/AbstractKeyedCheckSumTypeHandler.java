package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

public abstract class AbstractKeyedCheckSumTypeHandler extends AbstractCheckSumTypeHandler {

    public AbstractKeyedCheckSumTypeHandler(EncryptProvider encProvider, HashProvider hashProvider,
                                            int computeSize, int outputSize) {
        super(encProvider, hashProvider, computeSize, outputSize);
    }

    public byte[] makeKeyedChecksum(byte[] data,
                                    byte[] key, int usage) throws KrbException {
        return makeKeyedChecksum(data, 0, data.length, key, usage);
    }

    public byte[] makeKeyedChecksum(byte[] data, int start, int size,
                                    byte[] key, int usage) throws KrbException {
        int computeSize = computeSize();
        int outputSize = outputSize();

        int[] workLens = new int[] {computeSize, outputSize};
        byte[] workBuffer = new byte[computeSize];
        makeKeyedChecksumWith(workBuffer, workLens, data, start, size, key, usage);

        if (outputSize < computeSize) {
            byte[] output = new byte[outputSize];
            System.arraycopy(workBuffer, 0, output, 0, outputSize);
            return output;
        }
        return workBuffer;
    }

    protected void makeKeyedChecksumWith(byte[] workBuffer, int[] workLens,
                                                  byte[] data, int start, int size, byte[] key, int usage) throws KrbException {

    }

    public boolean verifyKeyedChecksum(byte[] data,
                                       byte[] key, int usage, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }
}
