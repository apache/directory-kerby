package org.apache.kerberos.kerb.spec.common;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1Integer;
import org.apache.haox.asn1.type.Asn1OctetString;
import org.apache.kerberos.kerb.spec.KrbSequenceType;

/**
 ETYPE-INFO-ENTRY        ::= SEQUENCE {
 etype           [0] Int32,
 salt            [1] OCTET STRING OPTIONAL
 }
 */
public class EtypeInfoEntry extends KrbSequenceType {
    private static int ETYPE = 0;
    private static int SALT = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ETYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(SALT, 1, Asn1OctetString.class)
    };

    public EtypeInfoEntry() {
        super(fieldInfos);
    }

    public EncryptionType getEtype() {
        return EncryptionType.fromValue(getFieldAsInt(ETYPE));
    }

    public void setEtype(EncryptionType etype) {
        setField(ETYPE, etype);
    }

    public byte[] getSalt() {
        return getFieldAsOctets(SALT);
    }

    public void setSalt(byte[] salt) {
        setFieldAsOctets(SALT, salt);
    }
}
