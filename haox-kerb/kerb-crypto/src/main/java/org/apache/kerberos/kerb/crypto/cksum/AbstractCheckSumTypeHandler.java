package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.AbstractCryptoTypeHandler;
import org.apache.kerberos.kerb.crypto.CheckSumTypeHandler;
import org.apache.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerberos.kerb.KrbException;

public abstract class AbstractCheckSumTypeHandler
        extends AbstractCryptoTypeHandler implements CheckSumTypeHandler {

    private int computeSize;
    private int outputSize;

    public AbstractCheckSumTypeHandler(EncryptProvider encProvider, HashProvider hashProvider,
                                       int computeSize, int outputSize) {
        super(encProvider, hashProvider);
        this.computeSize = computeSize;
        this.outputSize = outputSize;
    }

    @Override
    public String name() {
        return cksumType().getName();
    }

    @Override
    public String displayName() {
        return cksumType().getDisplayName();
    }

    @Override
    public int computeSize() {
        return computeSize;
    }

    @Override
    public int outputSize() {
        return outputSize;
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

    public int confounderSize() {
        return 0;
    }

    @Override
    public byte[] checksum(byte[] data) throws KrbException {
        return checksum(data, 0, data.length);
    }

    @Override
    public byte[] checksum(byte[] data, int start, int size) throws KrbException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean verify(byte[] data, byte[] checksum) throws KrbException {
        return verify(data, 0, data.length, checksum);
    }

    @Override
    public boolean verify(byte[] data, int start, int size, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] checksumWithKey(byte[] data,
                                  byte[] key, int usage) throws KrbException {
        return checksumWithKey(data, 0, data.length, key, usage);
    }

    @Override
    public byte[] checksumWithKey(byte[] data, int start, int size,
                                  byte[] key, int usage) throws KrbException {
        throw new UnsupportedOperationException();
    }
    @Override
    public boolean verifyWithKey(byte[] data,
                                 byte[] key, int usage, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }
}
