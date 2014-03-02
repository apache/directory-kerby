package org.haox.kerb.spec.type.common.impl;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbOctetString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionType;

public class EncryptedDataImpl extends AbstractSequenceType implements EncryptedData {
    public EncryptionType geteType() throws KrbException {
        KrbInteger value = getFieldAs(Tag.ETYPE, KrbInteger.class);
        return EncryptionType.fromValue(value);
    }

    public void seteType(EncryptionType eType) throws KrbException {
        setField(Tag.ETYPE, KrbTypes.makeInteger(eType));
    }

    public int getKvno() throws KrbException {
        KrbInteger value = getFieldAs(Tag.KVNO, KrbInteger.class);
        if (value != null) {
            return value.getValue().intValue();
        }
        return -1;
    }

    public void setKvno(int kvno) throws KrbException {
        setField(Tag.KVNO, KrbTypes.makeInteger(kvno));
    }

    public byte[] getCipher() throws KrbException {
        KrbOctetString value = getFieldAs(Tag.CIPHER, KrbOctetString.class);
        if (value != null) return value.getValue();
        return null;
    }

    public void setCipher(byte[] cipher) throws KrbException {
        KrbOctetString value = KrbTypes.makeOctetString(cipher);
        setField(Tag.CIPHER, value);
    }

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }
}
