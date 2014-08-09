package org.haox.kerb.crypto.key;

import org.haox.kerb.spec.KrbException;

public interface KeyMaker {

    public byte[] str2key(String string, String salt, byte[] param) throws KrbException;

    public byte[] random2Key(byte[] randomBits) throws KrbException;

    public byte[] dk(byte[] key, byte[] constant) throws KrbException;
}
