package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.crypto.Crc32;

public class Crc32Provider extends AbstractHashProvider {
    private byte[] output;

    public Crc32Provider() {
        super(4, 1);
    }

    @Override
    public void hash(byte[] data, int start, int size) {
        output = Crc32.byte2crc32sum_bytes(data, start, size);
    }

    @Override
    public byte[] output() {
        return output;
    }
}
