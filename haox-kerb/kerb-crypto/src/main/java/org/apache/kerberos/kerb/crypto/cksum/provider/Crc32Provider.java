package org.apache.kerberos.kerb.crypto.cksum.provider;

import org.apache.kerberos.kerb.crypto.Crc32;

public class Crc32Provider extends AbstractHashProvider {
    private byte[] output;

    public Crc32Provider() {
        super(4, 1);
    }

    @Override
    public void hash(byte[] data, int start, int size) {
        output = Crc32.crc(data, start, size);
    }

    @Override
    public byte[] output() {
        return output;
    }
}
