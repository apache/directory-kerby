package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 EncryptionKey   ::= SEQUENCE {
 keytype         [0] Int32 -- actually encryption type --,
 keyvalue        [1] OCTET STRING
 }
 */
public class EncryptionKey extends KrbSequenceType {
    private static int KEY_TYPE = 0;
    private static int KEY_VALUE = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(KEY_TYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(KEY_VALUE, 1, Asn1OctetString.class)
    };

    public EncryptionKey() {
        super(fieldInfos);
    }

    public EncryptionType getKeyType() {
        Integer value = getFieldAsInteger(KEY_TYPE);
        return EncryptionType.fromValue(value);
    }

    public void setKeyType(EncryptionType keyType) {
        setFieldAsInt(KEY_TYPE, keyType.getValue());
    }

    public byte[] getKeyData() {
        return getFieldAsOctetBytes(KEY_VALUE);
    }

    public void setKeyData(byte[] keyData) {
        setFieldAsOctetBytes(KEY_VALUE, keyData);
    }
}
