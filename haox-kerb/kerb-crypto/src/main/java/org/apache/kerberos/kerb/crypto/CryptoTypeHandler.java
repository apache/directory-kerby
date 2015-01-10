package org.apache.kerberos.kerb.crypto;

import org.apache.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerberos.kerb.crypto.enc.EncryptProvider;

public interface CryptoTypeHandler {

    public String name();

    public String displayName();

    public EncryptProvider encProvider();

    public HashProvider hashProvider();
}
