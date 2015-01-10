package org.apache.kerberos.kerb.crypto.key;

import org.apache.kerberos.kerb.KrbException;

public interface KeyMaker {

    public byte[] str2key(String string, String salt, byte[] param) throws KrbException;

    public byte[] random2Key(byte[] randomBits) throws KrbException;
}
