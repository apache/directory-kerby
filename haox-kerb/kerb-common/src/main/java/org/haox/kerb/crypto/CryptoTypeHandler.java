package org.haox.kerb.crypto;

import org.haox.kerb.crypto.cksum.HashProvider;
import org.haox.kerb.crypto.enc.EncryptProvider;

public interface CryptoTypeHandler {

    public String name();

    public String displayName();

    public EncryptProvider encProvider();

    public HashProvider hashProvider();
}
