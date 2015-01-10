package org.apache.kerberos.kerb.crypto;

import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.common.CheckSumType;

public interface CheckSumTypeHandler extends CryptoTypeHandler {

    public int confounderSize();

    public CheckSumType cksumType();

    public int computeSize(); // allocation size for checksum computation

    public int outputSize(); // possibly truncated output size

    public boolean isSafe();

    public int cksumSize();

    public int keySize();

    public byte[] checksum(byte[] data) throws KrbException;

    public byte[] checksum(byte[] data, int start, int len) throws KrbException;

    public boolean verify(byte[] data, byte[] checksum) throws KrbException;

    public boolean verify(byte[] data, int start, int len, byte[] checksum) throws KrbException;

    public byte[] checksumWithKey(byte[] data,
                                  byte[] key, int usage) throws KrbException;

    public byte[] checksumWithKey(byte[] data, int start, int len,
                                  byte[] key, int usage) throws KrbException;

    public boolean verifyWithKey(byte[] data,
                                 byte[] key, int usage, byte[] checksum) throws KrbException;
}
