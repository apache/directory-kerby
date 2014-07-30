package org.haox.kerb.crypto.encryption;

import org.haox.kerb.spec.type.common.EncryptionKey;

/**
 * krb5_hash_provider
 */
public interface HashProvider {

    public String getHashName();
    public int getHashSize();
    public int getBlockSize();

    public byte[] hash(byte[] data);
}
