package org.haox.kerb.crypto2.cksum;

import org.haox.kerb.crypto2.Crc32;
import org.haox.kerb.spec.type.common.CheckSumType;

public class Crc32CheckSum extends AbstractCheckSumTypeHandler {

    public Crc32CheckSum() {
        super(null, null);
    }

    public int confounderSize() {
        return 0;
    }

    public CheckSumType cksumType() {
        return CheckSumType.CRC32;
    }

    public boolean isSafe() {
        return false;
    }

    public int cksumSize() {
        return 4;
    }

    public int keySize() {
        return 0;
    }

    @Override
    public byte[] calculateChecksum(byte[] data) {
        return Crc32.byte2crc32sum_bytes(data, data.length);
    }

    public static byte[] int2quad(long input) {
        byte[] output = new byte[4];
        for (int i = 0; i < 4; i++) {
            output[i] = (byte)((input >>> (i * 8)) & 0xff);
        }
        return output;
    }

    public static long bytes2long(byte[] input) {
        long result = 0;

        result |= (((long)input[0]) & 0xffL) << 24;
        result |= (((long)input[1]) & 0xffL) << 16;
        result |= (((long)input[2]) & 0xffL) << 8;
        result |= (((long)input[3]) & 0xffL);
        return result;
    }
}
