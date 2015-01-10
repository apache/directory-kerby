package org.apache.kerberos.kerb.spec.pa.token;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1OctetString;
import org.apache.haox.asn1.type.Asn1Utf8String;
import org.apache.kerberos.kerb.spec.KrbSequenceType;

/**
 TokenInfo ::= SEQUENCE {
    flags            [0] TokenFlags,
    tokenVendor      [1] UTF8String,
 }
 */
public class TokenInfo extends KrbSequenceType {
    private static int FLAGS = 0;
    private static int TOKEN_VENDOR = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(FLAGS, Asn1OctetString.class, true),
            new Asn1FieldInfo(TOKEN_VENDOR, Asn1Utf8String.class),
    };

    public TokenInfo() {
        super(fieldInfos);
    }

    public TokenFlags getFlags() {
        return getFieldAs(FLAGS, TokenFlags.class);
    }

    public void setFlags(TokenFlags flags) {
        setFieldAs(FLAGS, flags);
    }

    public String getTokenVendor() {
        return getFieldAsString(TOKEN_VENDOR);
    }

    public void setTokenVendor(String tokenVendor) {
        setFieldAs(TOKEN_VENDOR, new Asn1Utf8String(tokenVendor));
    }

}
