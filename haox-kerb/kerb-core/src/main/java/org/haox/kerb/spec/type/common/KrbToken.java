package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.type.KrbSequenceType;

import java.nio.ByteBuffer;
import java.util.Map;

/**
 KRB-TOKEN_VALUE ::= SEQUENCE {
    token-format [0] INTEGER,
    token-value  [1] OCTET STRING,
 }
 */
public class KrbToken extends KrbSequenceType {
    private static KrbTokenEncoder tokenEncoder;

    private static int TOKEN_FORMAT = 0;
    private static int TOKEN_VALUE = 1;

    private Map<String, Object> attributes;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(TOKEN_FORMAT, 0, Asn1Integer.class),
            new Asn1FieldInfo(TOKEN_VALUE, 1, Asn1OctetString.class)
    };

    public KrbToken() {
        super(fieldInfos);
    }

    @Override
    public void encode(ByteBuffer buffer) {
        setTokenValue(tokenEncoder.encode(this));
        super.encode(buffer);
    }

    /*
    @Override
    public void decode(ByteBuffer content) throws IOException {
        super.decode(content);
        this.attributes = tokenEncoder.decode(this);
    }
    */

    public static void setTokenEncoder(KrbTokenEncoder encoder) {
        tokenEncoder = encoder;
    }

    public TokenFormat getTokenFormat() {
        Integer value = getFieldAsInteger(TOKEN_FORMAT);
        return TokenFormat.fromValue(value);
    }

    public void setTokenFormat(TokenFormat tokenFormat) {
        setFieldAsInt(TOKEN_FORMAT, tokenFormat.getValue());
    }

    public byte[] getTokenValue() {
        return getFieldAsOctets(TOKEN_VALUE);
    }

    public void setTokenValue(byte[] tokenValue) {
        setFieldAsOctets(TOKEN_VALUE, tokenValue);
    }

    public Map<String, Object> getAttributes() {
        if (attributes == null) {
            this.attributes = tokenEncoder.decode(this);
        }
        return attributes;
    }

    public String getPrincipal() {
        return (String) attributes.get("sub");
    }

}
