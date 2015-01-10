package org.apache.haox.asn1.type;

import org.apache.haox.asn1.UniversalTag;

import java.io.IOException;
import java.math.BigInteger;

public class Asn1Integer extends Asn1Simple<Integer>
{
    public Asn1Integer() {
        this(null);
    }

    public Asn1Integer(Integer value) {
        super(UniversalTag.INTEGER, value);
    }

    @Override
    protected void toBytes() {
        setBytes(BigInteger.valueOf(getValue()).toByteArray());
    }

    @Override
    protected void toValue() throws IOException {
        setValue(new BigInteger(getBytes()).intValue());
    }
}
