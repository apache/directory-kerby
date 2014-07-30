package org.haox.kerb.crypto.encryption;

import org.haox.kerb.spec.type.common.EncryptionKey;

/**
 * krb5_enc_provider
 */
public interface EncryptProvider {

    public int getKeyInputSize();
    public int getKeySize();
    public int getBlockSize();

    public void encrypt(EncryptionKey key, byte[] cipherState, byte[] data);
    public void decrypt(EncryptionKey key, byte[] cipherState, byte[] data);
    public byte[] cbcMac(EncryptionKey key, byte[] data, byte[] iv);
    public byte[] initState(EncryptionKey key, KeyUsage keyUsage);
}
