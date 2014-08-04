package org.haox.kerb.crypto2.enc;

import org.haox.kerb.spec.KrbException;

/**
 * krb5_enc_provider
 */
public interface EncryptProvider {

    public int keyInputSize(); //input size to make_key
    public int keySize(); //output key size
    public int blockSize(); //crypto block size

    public void encrypt(byte[] key, byte[] cipherState, byte[] data) throws KrbException;
    public void decrypt(byte[] key, byte[] cipherState, byte[] data) throws KrbException;
    public void cbcMac(byte[] key, byte[] iv, byte[] data);
    public byte[] initState(byte[] key, int keyUsage);
    public void cleanState();
    public void cleanKey();
}
