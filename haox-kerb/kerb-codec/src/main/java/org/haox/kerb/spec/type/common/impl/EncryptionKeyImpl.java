package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbFactory;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbOctetString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

public class EncryptionKeyImpl extends AbstractSequenceType implements EncryptionKey {
    public EncryptionType getKeyType() throws KrbException {
        KrbInteger value = getFieldAs(Tag.KEY_TYPE, KrbInteger.class);
        return EncryptionType.fromValue(value);
    }

    public void setKeyType(EncryptionType keyType) throws KrbException {
        setField(Tag.KEY_TYPE, KrbTypes.makeInteger(keyType));
    }

    public byte[] getKeyData() throws KrbException {
        KrbOctetString value = getFieldAs(Tag.KEY_VALUE, KrbOctetString.class);
        if (value != null) return value.getValue();
        return null;
    }

    public void setKeyData(byte[] keyData) throws KrbException {
        KrbOctetString value = KrbFactory.create(KrbOctetString.class);
        value.setValue(keyData);
        setField(Tag.KEY_VALUE, value);
    }

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }
}
