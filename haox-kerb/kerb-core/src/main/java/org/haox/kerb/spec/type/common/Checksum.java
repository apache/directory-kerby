package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 Checksum        ::= SEQUENCE {
 cksumtype       [0] Int32,
 checksum        [1] OCTET STRING
 }
 */
public class Checksum extends KrbSequenceType {
    private static int CKSUM_TYPE = 0;
    private static int CHECK_SUM = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(CKSUM_TYPE, 0, Asn1Integer.class),
        new Asn1FieldInfo(CHECK_SUM, 1, Asn1OctetString.class)
    };

    public Checksum() {
        super(fieldInfos);
    }

    public ChecksumType getCksumtype() throws KrbException {
        Integer value = getFieldAsInteger(CKSUM_TYPE);
        return ChecksumType.fromValue(value);
    }

    public void setCksumtype(ChecksumType cksumtype) throws KrbException {
        setFieldAsInt(CKSUM_TYPE, cksumtype.getValue());
    }

    public byte[] getChecksum() throws KrbException {
        return getFieldAsOctets(CHECK_SUM);
    }

    public void setChecksum(byte[] checksum) throws KrbException {
        setFieldAsOctets(CHECK_SUM, checksum);
    }
}
