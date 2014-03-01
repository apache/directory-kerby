package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractSequenceKrbType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbFactory;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbOctetString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.ChecksumType;
import org.haox.kerb.spec.type.common.MyChecksum;

public class MyChecksumImpl extends AbstractSequenceKrbType implements MyChecksum {
    public ChecksumType getCksumtype() {
        KrbInteger value = getFieldAs(Tag.CKSUM_TYPE, KrbInteger.class);
        return ChecksumType.fromValue(value);
    }

    public void setCksumtype(ChecksumType cksumtype) throws KrbException {
        setField(Tag.CKSUM_TYPE, cksumtype.asInteger());
    }

    public byte[] getChecksum() {
        KrbOctetString value = getFieldAs(Tag.CHECK_SUM, KrbOctetString.class);
        if (value != null) return value.getValue();
        return null;
    }

    public void setChecksum(byte[] checksum) throws KrbException {
        KrbOctetString value = KrbFactory.create(KrbOctetString.class);
        value.setValue(checksum);
        setField(Tag.CHECK_SUM, value);
    }

    @Override
    protected KrbTag[] getTags() {
        return MyChecksum.Tag.values();
    }
}
