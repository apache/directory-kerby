package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.crypto.cksum.AbstractCheckSumTypeHandler;
import org.haox.kerb.crypto.cksum.HashProvider;
import org.haox.kerb.spec.KrbException;

public abstract class AbstractUnkeyedCheckSumTypeHandler extends AbstractCheckSumTypeHandler {

    public AbstractUnkeyedCheckSumTypeHandler(HashProvider hashProvider,
                                              int computeSize, int outputSize) {
        super(null, hashProvider, computeSize, outputSize);
    }

    @Override
    public byte[] checksum(byte[] data, int start, int len) throws KrbException {
        int outputSize = outputSize();

        HashProvider hp = hashProvider();
        hp.hash(data, start, len);
        byte[] workBuffer = hp.output();

        if (outputSize < workBuffer.length) {
            byte[] output = new byte[outputSize];
            System.arraycopy(workBuffer, 0, output, 0, outputSize);
            return output;
        }
        return workBuffer;
    }

    @Override
    public boolean verify(byte[] data, int start, int len, byte[] checksum) throws KrbException {
        byte[] newCksum = checksum(data, start, len);
        return checksumEqual(newCksum, checksum);
    }
}
