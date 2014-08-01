package org.haox.kerb.crypto.encryption;

import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

/**
 * krb5_keytypes
 */
public interface KeyType {

    public EncryptionType getEncryptType();
    public String getName();
    public String[] getAliases();
    public String getOutString();
    public EncryptProvider getEncProvider();
    public HashProvider getHashProvider();
    public int getPrfLength();
    public int cryptoLength(int cryptoType);
    public void encrypt(EncryptionKey key, KeyUsage keyUsage, byte[] iv, byte[] data);
    public void decrypt(EncryptionKey key, KeyUsage keyUsage, byte[] iv, byte[] data);
    public void str2key(String str, byte[] salt, byte[] param, EncryptionKey key);
    public void rand2key(byte[] random, EncryptionKey key);
    public byte[] prf(EncryptionKey key, byte[] data);
    public int getRequiredChecksumType();
    public int getFlags();
}
