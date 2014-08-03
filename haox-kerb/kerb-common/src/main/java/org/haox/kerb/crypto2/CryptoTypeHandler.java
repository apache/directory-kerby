package org.haox.kerb.crypto2;

import org.haox.kerb.crypto2.cksum.HashProvider;
import org.haox.kerb.crypto2.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

public interface CryptoTypeHandler {

    public String name();

    public String displayName();

    public EncryptProvider encProvider();

    public HashProvider hashProvider();
}
