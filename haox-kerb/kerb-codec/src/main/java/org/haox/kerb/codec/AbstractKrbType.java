package org.haox.kerb.codec;

import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.common.ChecksumType;
import org.haox.kerb.spec.type.common.MyChecksum;

public class AbstractKrbType implements KrbType, KrbEncodable {
    protected Class<? extends KrbType>[] fieldTypes;

    @Override
    public byte[] encode() {
        return new byte[0];
    }

    @Override
    public void decode(byte[] content) {

    }
}
