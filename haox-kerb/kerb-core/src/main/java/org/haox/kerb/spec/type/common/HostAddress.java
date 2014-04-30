package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbSequenceType;

/*
HostAddress     ::= SEQUENCE  {
        addr-type       [0] Int32,
        address         [1] OCTET STRING
}
 */
public class HostAddress extends KrbSequenceType {
    private static int ADDR_TYPE = 0;
    private static int ADDRESS = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ADDR_TYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(ADDRESS, 1, Asn1OctetString.class)
    };

    public HostAddress() {
        super(fieldInfos);
    }

    public HostAddrType getAddrType() throws KrbException {
        Integer value = getFieldAsInteger(ADDR_TYPE);
        return HostAddrType.fromValue(value);
    }

    public void setAddrType(HostAddrType addrType) throws KrbException {
        setFieldAs(ADDR_TYPE, new Asn1Integer(addrType.getValue()));
    }

    public byte[] getAddress() throws KrbException {
        return getFieldAsOctetBytes(ADDRESS);
    }

    public void setAddress(byte[] address) throws KrbException {
        setFieldAsOctetBytes(ADDRESS, address);
    }
}
