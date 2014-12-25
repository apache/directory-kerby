package org.haox.token;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1Integer;
import org.apache.haox.asn1.type.Asn1OctetString;
import org.apache.haox.asn1.type.Asn1SequenceType;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
     ad-type         [0] Int32,
     ad-data         [1] OCTET STRING
 }
 */
public class AuthzDataEntry extends Asn1SequenceType {
    static int AD_TYPE = 0;
    static int AD_DATA = 1;

    public AuthzDataEntry() {
        super(new Asn1FieldInfo[] {
                new Asn1FieldInfo(AD_TYPE, Asn1Integer.class),
                new Asn1FieldInfo(AD_DATA, Asn1OctetString.class)
        });
    }

    public int getAuthzType() {
        Integer value = getFieldAsInteger(AD_TYPE);
        return value;
    }

    public byte[] getAuthzData() {
        return getFieldAsOctets(AD_DATA);
    }
}
