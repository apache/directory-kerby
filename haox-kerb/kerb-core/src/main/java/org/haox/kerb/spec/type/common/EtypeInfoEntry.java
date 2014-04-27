package org.haox.kerb.spec.type.common;

import org.haox.asn1.Asn1Tag;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 ETYPE-INFO-ENTRY        ::= SEQUENCE {
 etype           [0] Int32,
 salt            [1] OCTET STRING OPTIONAL
 }
 */
public class EtypeInfoEntry extends KrbSequenceType {
    private static int ETYPE = 0;
    private static int SALT = 1;

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(ETYPE, 0, Asn1Integer.class),
            new Asn1Tag(SALT, 1, Asn1OctetString.class)
    };

    public EtypeInfoEntry() {
        super(tags);
    }

    public int getEtype() {
        return getFieldAsInt(ETYPE);
    }

    public void setEtype(int etype) {
        setFieldAsInt(ETYPE, etype);
    }

    public byte[] getSalt() {
        return getFieldAsOctetBytes(SALT);
    }

    public void setSalt(byte[] salt) {
        setFieldAsOctetBytes(SALT, salt);
    }
}
