package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.LimitedByteBuffer;
import org.haox.asn1.UniversalTag;

import java.io.IOException;

public class Asn1Boolean extends AbstractAsn1Simple<Boolean>
{
    private static final byte[] TRUE_BYTE = new byte[] { (byte)0xff };
    private static final byte[] FALSE_BYTE = new byte[] { (byte)0x00 };

    public static final Asn1Boolean TRUE = new Asn1Boolean(true);
    public static final Asn1Boolean FALSE = new Asn1Boolean(false);

    public Asn1Boolean() {
        this(null);
    }

    public Asn1Boolean(Boolean value) {
        super(UniversalTag.BOOLEAN, value);
    }

    @Override
    protected int encodingBodyLength(EncodingOption encodingOption) {
        return 1;
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        if (content.hasLeft() != 1) {
            throw new IOException("More than 1 byte found for Boolean");
        }
        super.decodeBody(content);
    }

    protected void toBytes() {
        setBytes(getValue() ? TRUE_BYTE : FALSE_BYTE);
    }

    protected void toValue() throws IOException {
        byte[] bytes = getBytes();
        if (bytes[0] == 0) {
            setValue(false);
        } else if (bytes[0] == 0xff) {
            setValue(true);
        } else {
            setValue(true);
        }
    }
}
