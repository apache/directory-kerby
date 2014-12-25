package org.apache.kerberos.kerb.spec.common;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1Integer;
import org.apache.haox.asn1.type.Asn1OctetString;
import org.apache.kerberos.kerb.spec.KerberosString;
import org.apache.kerberos.kerb.spec.KrbSequenceType;

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

    public EncryptionType getEtype() {
        return EncryptionType.fromValue(getFieldAsInt(ETYPE));
    }

    public void setEtype(EncryptionType etype) {
        setField(ETYPE, etype);
    }

    public String getSalt() {
        return getFieldAsString(SALT);
    }

    public void setSalt(String salt) {
        setFieldAsString(SALT, salt);
    }

    public byte[] getS2kParams() {
        return getFieldAsOctets(S2KPARAMS);
    }

    public void setS2kParams(byte[] s2kParams) {
        setFieldAsOctets(S2KPARAMS, s2kParams);
    }
}
