package org.haox.asn1.type;

import org.haox.asn1.UniversalTag;

import java.io.IOException;
import java.math.BigInteger;

public class Asn1BigInteger extends Asn1Simple<BigInteger>
{
    public Asn1BigInteger() {
        this(null);
    }

    public Asn1BigInteger(long value) {
        this(BigInteger.valueOf(value));
    }

    public Asn1BigInteger(BigInteger value) {
        super(UniversalTag.INTEGER, value);
    }

    protected void toBytes() {
        setBytes(getValue().toByteArray());
    }

    protected void toValue() throws IOException {
        setValue(new BigInteger(getBytes()));
    }
}
