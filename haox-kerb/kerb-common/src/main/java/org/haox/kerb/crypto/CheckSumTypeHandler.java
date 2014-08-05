package org.haox.kerb.crypto;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

public interface CheckSumTypeHandler extends CryptoTypeHandler {

    public int confounderSize();

    public CheckSumType cksumType();

    public int computeSize(); // allocation size for checksum computation

    public int outputSize(); // possibly truncated output size

    public boolean isSafe();

    public int cksumSize();

    public int keySize();

    public byte[] calculateChecksum(byte[] data) throws KrbException;

    public byte[] calculateChecksum(byte[] data, int start, int size) throws KrbException;

    public boolean verifyChecksum(byte[] data, byte[] checksum) throws KrbException;

    public byte[] calculateKeyedChecksum(byte[] data,
                                         byte[] key, int usage) throws KrbException;

    public byte[] calculateKeyedChecksum(byte[] data, int start, int size,
        byte[] key, int usage) throws KrbException;

    public boolean verifyKeyedChecksum(byte[] data,
        byte[] key, int usage, byte[] checksum) throws KrbException;
}
