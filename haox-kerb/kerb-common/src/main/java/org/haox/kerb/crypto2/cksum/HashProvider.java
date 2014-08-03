package org.haox.kerb.crypto2.cksum;

/**
 * krb5_hash_provider
 */
public interface HashProvider {

    public int hashSize();
    public int blockSize();

    public byte[] hash(byte[] data);
}
