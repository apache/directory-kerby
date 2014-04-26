package org.haox.asn1.type;

import org.haox.asn1.UniversalTag;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;

public class Asn1Integer extends AbstractAsn1Simple<Integer>
{
    public Asn1Integer() {
        this(null);
    }

    public Asn1Integer(Integer value) {
        super(UniversalTag.INTEGER, value);
    }

    protected void toBytes() {
        setBytes(ByteBuffer.allocate(4).putInt(getValue()).array());
    }

    protected void toValue() throws IOException {
        setValue(new BigInteger(getBytes()).intValue());
    }
}
