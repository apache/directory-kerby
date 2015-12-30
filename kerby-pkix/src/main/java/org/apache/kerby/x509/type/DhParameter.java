package org.apache.kerby.x509.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceType;

import java.math.BigInteger;

public class DhParameter extends Asn1SequenceType {
    protected enum DhParameterField implements EnumType {
        P,
        G,
        Q;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(DhParameterField.P, Asn1Integer.class),
            new Asn1FieldInfo(DhParameterField.G, Asn1Integer.class),
            new Asn1FieldInfo(DhParameterField.Q, Asn1Integer.class),
    };

    public DhParameter() {
        super(fieldInfos);
    }

    public void setP(BigInteger p) {
        setFieldAsInt(DhParameterField.P, p);
    }

    public BigInteger getP() {
        Asn1Integer p = getFieldAs(DhParameterField.P, Asn1Integer.class);
        return p.getValue();
    }

    public void setG(BigInteger g) {
        setFieldAsInt(DhParameterField.G, g);
    }

    public BigInteger getG() {
        Asn1Integer g = getFieldAs(DhParameterField.G, Asn1Integer.class);
        return g.getValue();
    }

    public void setQ(BigInteger q) {
        setFieldAsInt(DhParameterField.Q, q);
    }

    public BigInteger getQ() {
        Asn1Integer q = getFieldAs(DhParameterField.Q, Asn1Integer.class);
        return q.getValue();
    }
}
