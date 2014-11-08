package org.haox.kerb.spec.type.pa.pkinit;

import org.haox.asn1.type.Asn1Choice;
import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1OctetString;

/**
 PA-PK-AS-REP ::= CHOICE {
    dhInfo                  [0] DHRepInfo,
    encKeyPack              [1] IMPLICIT OCTET STRING,
 }
 */
public class PaPkAsRep extends Asn1Choice {
    private static int DH_INFO = 0;
    private static int ENCKEY_PACK = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(DH_INFO, DHRepInfo.class),
            new Asn1FieldInfo(ENCKEY_PACK, Asn1OctetString.class, true)
    };

    public PaPkAsRep() {
        super(fieldInfos);
    }

    public DHRepInfo getDHRepInfo() {
        return getFieldAs(DH_INFO, DHRepInfo.class);
    }

    public void setDHRepInfo(DHRepInfo dhRepInfo) {
        setFieldAs(DH_INFO, dhRepInfo);
    }

    public byte[] getEncKeyPack() {
        return getFieldAsOctets(ENCKEY_PACK);
    }

    public void setEncKeyPack(byte[] encKeyPack) {
        setFieldAsOctets(ENCKEY_PACK, encKeyPack);
    }
}
