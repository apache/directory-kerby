package org.haox.kerb.codec;

import org.bouncycastle.asn1.DEROctetString;
import org.haox.kerb.spec.KrbCodecMessageCode;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbThrow;
import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.common.ChecksumType;
import org.haox.kerb.spec.type.common.MyChecksum;

public abstract class AbstractKrbType implements KrbType, KrbEncodable {
    @Override
    public boolean isSimple() {
        return true;
    }

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
