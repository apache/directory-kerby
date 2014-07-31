package org.haox.kerb.crypto2.enc;

import org.haox.kerb.crypto2.EncryptionTypeHandler;

public abstract class AbstractEncryptionTypeHandler implements EncryptionTypeHandler {

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
