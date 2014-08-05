package org.haox.kerb.crypto.cksum;

import org.haox.kerb.spec.KrbException;

/**
 * krb5_hash_provider
 */
public interface HashProvider {

    public int hashSize();
    public int blockSize();

    public byte[] hash(byte[] data, int start, int size) throws KrbException;
    public byte[] hash(byte[] data) throws KrbException;
}
