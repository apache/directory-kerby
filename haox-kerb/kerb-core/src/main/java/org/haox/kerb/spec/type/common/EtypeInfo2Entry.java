package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.type.KerberosString;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 ETYPE-INFO2-ENTRY       ::= SEQUENCE {
 etype           [0] Int32,
 salt            [1] KerberosString OPTIONAL,
 s2kparams       [2] OCTET STRING OPTIONAL
 }
 */
public class EtypeInfo2Entry extends KrbSequenceType {
    private static int ETYPE = 0;
    private static int SALT = 1;
    private static int S2KPARAMS = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ETYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(SALT, 1, KerberosString.class),
            new Asn1FieldInfo(S2KPARAMS, 2, Asn1OctetString.class)
    };

    public EtypeInfo2Entry() {
        super(fieldInfos);
    }

    public int getEtype() {
        return getFieldAsInt(ETYPE);
    }

    public void setEtype(int etype) {
        setFieldAsInt(ETYPE, etype);
    }

    public String getSalt() {
        return getFieldAsString(SALT);
    }

    public void setSalt(String salt) {
        setFieldAsString(SALT, salt);
    }

    public byte[] getS2kParams() {
        return getFieldAsOctetBytes(S2KPARAMS);
    }

    public void setS2kParams(byte[] s2kParams) {
        setFieldAsOctetBytes(S2KPARAMS, s2kParams);
    }
}
