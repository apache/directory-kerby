package org.haox.kerb.crypto2;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

public interface CheckSumTypeHandler {

    public int confounderSize();

    public CheckSumType cksumType();

    public boolean isSafe();

    public int cksumSize();

    public int keySize();

    public byte[] calculateChecksum(byte[] data) throws KrbException;

    public boolean verifyChecksum(byte[] data, byte[] checksum) throws KrbException;

    public byte[] calculateKeyedChecksum(byte[] data,
        byte[] key, int usage) throws KrbException;

    public boolean verifyKeyedChecksum(byte[] data,
        byte[] key, int usage, byte[] checksum) throws KrbException;
}
