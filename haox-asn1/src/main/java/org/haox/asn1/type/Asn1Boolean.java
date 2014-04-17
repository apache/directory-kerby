package org.haox.asn1.type;

import java.io.IOException;

public class Asn1Boolean extends AbstractAsn1Primitive<Boolean>
{
    private static final byte[] TRUE_BYTE = new byte[] { (byte)0xff };
    private static final byte[] FALSE_BYTE = new byte[] { (byte)0x00 };

    public static final Asn1Boolean TRUE = new Asn1Boolean(true);
    public static final Asn1Boolean FALSE = new Asn1Boolean(false);

    public Asn1Boolean() {
        this(null);
    }

    public Asn1Boolean(Boolean value) {
        super(value, BerTag.BOOLEAN);
    }

    @Override
    protected byte[] body() {
        return getValue() ? TRUE_BYTE : FALSE_BYTE;
    }

    @Override
    protected int bodyLength() {
        return 1;
    }

    @Override
    protected void decodeValue(LimitedByteBuffer content) throws IOException {
        byte[] bytes = content.readAllBytes();

        if (bytes.length != 1) {
            throw new IOException("More than 1 byte found for Boolean");
        }

        if (bytes[0] == 0) {
            setValue(false);
        } else if (bytes[0] == 0xff) {
            setValue(true);
        } else {
            setValue(true);
        }
    }
}
