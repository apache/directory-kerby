package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.AbstractSequenceType;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.asn1.type.Asn1Tag;
import org.haox.kerb.spec.KrbException;

/**
 EncryptionKey   ::= SEQUENCE {
 keytype         [0] Int32 -- actually encryption type --,
 keyvalue        [1] OCTET STRING
 }
 */
public class EncryptionKey extends AbstractSequenceType {
    private static int KEY_TYPE = 0;
    private static int KEY_VALUE = 1;

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(KEY_TYPE, 0, Asn1Integer.class),
            new Asn1Tag(KEY_VALUE, 1, Asn1OctetString.class)
    };

    @Override
    protected Asn1Tag[] getTags() {
        return tags;
    }

    public EncryptionType getKeyType() throws KrbException {
        Integer value = getFieldAsInteger(KEY_TYPE);
        return EncryptionType.fromValue(value);
    }

    public void setKeyType(EncryptionType keyType) throws KrbException {
        setFieldAsInt(KEY_TYPE, keyType.getValue());
    }

    public byte[] getKeyData() throws KrbException {
        return getFieldAsOctetBytes(KEY_VALUE);
    }

    public void setKeyData(byte[] keyData) throws KrbException {
        setFieldAsOctetBytes(KEY_VALUE, keyData);
    }
}
