package org.haox.kerb.codec;

import org.haox.kerb.spec.KrbCodecMessageCode;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbThrow;
import org.haox.kerb.spec.type.KrbType;

public abstract class AbstractKrbType implements KrbType, KrbEncodable {
    @Override
    public byte[] encode()  throws KrbException {
        KrbThrow.out(KrbCodecMessageCode.NOT_IMPLEMENTED);
        return null;
    }

    @Override
    public void decode(byte[] content)  throws KrbException {
        KrbThrow.out(KrbCodecMessageCode.NOT_IMPLEMENTED);
    }
}
