package org.haox.kerb.crypto2.cksum.provider;

import org.haox.kerb.crypto2.Crc32;

public class Crc32Provider extends AbstractHashProvider {

    public Crc32Provider() {
        super(4, 1);
    }

    @Override
    public byte[] hash(byte[] data) {
        return Crc32.byte2crc32sum_bytes(data, data.length);
    }
}
