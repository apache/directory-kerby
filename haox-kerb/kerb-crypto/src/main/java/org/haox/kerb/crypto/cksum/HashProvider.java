package org.haox.kerb.crypto.cksum;

import org.haox.kerb.KrbException;

/**
 * krb5_hash_provider
 */
public interface HashProvider {

    public int hashSize();
    public int blockSize();

    public void hash(byte[] data, int start, int size) throws KrbException;
    public void hash(byte[] data) throws KrbException;
    public byte[] output();
}
