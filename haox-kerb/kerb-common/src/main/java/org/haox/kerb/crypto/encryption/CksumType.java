package org.haox.kerb.crypto.encryption;

import org.haox.kerb.crypto2.cksum.HashProvider;
import org.haox.kerb.crypto2.enc.EncryptProvider;
import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.type.common.EncryptionKey;

/**
 * krb5_cksumtypes
 */
public interface CksumType {

    public int getChecksumType();
    public String getName();
    public String[] getAliases();
    public String getOutString();
    public EncryptProvider getEncProvider();
    public HashProvider getHashProvider();
    public byte[] checksum(EncryptionKey key, KeyUsage keyUsage, byte[] data);
    public boolean verify(EncryptionKey key, KeyUsage keyUsage, byte[] data, byte[] input);
    public int getComputeSize();
    public int getOutputSize();
    public int getFlags();
}
