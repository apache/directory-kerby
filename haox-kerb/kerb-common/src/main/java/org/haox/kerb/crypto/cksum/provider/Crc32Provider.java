package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.crypto.Crc32;

public class Crc32Provider extends AbstractHashProvider {

    public Crc32Provider() {
        super(4, 1);
    }

    @Override
    public byte[] hash(byte[] data, int start, int size) {
        return Crc32.byte2crc32sum_bytes(data, start, size);
    }
}
