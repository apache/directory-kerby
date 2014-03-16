package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbOctetString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.HostAddrType;
import org.haox.kerb.spec.type.common.HostAddress;
import org.haox.kerb.spec.type.common.TransitedEncoding;
import org.haox.kerb.spec.type.common.TransitedEncodingType;

public class TransitedEncodingImpl extends AbstractSequenceType implements TransitedEncoding {
    public TransitedEncodingType getTrType() throws KrbException {
        KrbInteger value = getFieldAs(Tag.TR_TYPE, KrbInteger.class);
        return TransitedEncodingType.fromValue(value);
    }

    public void setTrType(TransitedEncodingType trType) throws KrbException {
        setField(Tag.TR_TYPE, KrbTypes.makeInteger(trType));
    }

    public byte[] getContents() throws KrbException {
        KrbOctetString value = getFieldAs(Tag.CONTENTS, KrbOctetString.class);
        if (value != null) return value.getValue();
        return null;
    }

    public void setContents(byte[] contents) throws KrbException {
        KrbOctetString value = KrbTypes.makeOctetString(contents);
        setField(Tag.CONTENTS, value);
    }

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }
}
