package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbFactory;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbOctetString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.Checksum;
import org.haox.kerb.spec.type.common.ChecksumType;

public class ChecksumImpl extends AbstractSequenceType implements Checksum {
    public ChecksumType getCksumtype() throws KrbException {
        KrbInteger value = getFieldAs(Tag.CKSUM_TYPE, KrbInteger.class);
        return ChecksumType.fromValue(value);
    }

    public void setCksumtype(ChecksumType cksumtype) throws KrbException {
        setField(Tag.CKSUM_TYPE, KrbTypes.makeInteger(cksumtype));
    }

    public byte[] getChecksum() throws KrbException {
        KrbOctetString value = getFieldAs(Tag.CHECK_SUM, KrbOctetString.class);
        if (value != null) return value.getValue();
        return null;
    }

    public void setChecksum(byte[] checksum) throws KrbException {
        KrbOctetString value = KrbTypes.makeOctetString(checksum);
        setField(Tag.CHECK_SUM, value);
    }

    @Override
    public KrbTag[] getTags() {
        return Checksum.Tag.values();
    }
}
