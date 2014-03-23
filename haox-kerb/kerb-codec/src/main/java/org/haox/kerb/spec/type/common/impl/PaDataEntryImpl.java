package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbOctetString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.PaDataEntry;
import org.haox.kerb.spec.type.common.PaDataType;

public class PaDataEntryImpl extends AbstractSequenceType implements PaDataEntry {
    public PaDataType getPaDataType() throws KrbException {
        KrbInteger value = getFieldAs(Tag.PADATA_TYPE, KrbInteger.class);
        return PaDataType.fromValue(value);
    }

    public void setPaDataType(PaDataType paDataType) throws KrbException {
        setField(Tag.PADATA_TYPE, KrbTypes.makeInteger(paDataType));
    }

    public byte[] getPaDataValue() throws KrbException {
        KrbOctetString value = getFieldAs(Tag.PADATA_VALUE, KrbOctetString.class);
        if (value != null) return value.getValue();
        return null;
    }

    public void setPaDataValue(byte[] paDataValue) throws KrbException {
        KrbOctetString value = KrbTypes.makeOctetString(paDataValue);
        setField(Tag.PADATA_VALUE, value);
    }

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }
}
