package org.apache.kerby.kerberos.kerb.spec.pa.pkinit;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceType;

import java.math.BigInteger;

public class DHParameter extends Asn1SequenceType {

    private static final int P = 0;
    private static final int G = 1;
    private static final int Q = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(P, Asn1Integer.class),
            new Asn1FieldInfo(G, Asn1Integer.class),
            new Asn1FieldInfo(Q, Asn1Integer.class),
    };

    public DHParameter() {
        super(fieldInfos);
    }

    public void setP(BigInteger p) {
        setFieldAsBigInteger(P, p);
    }

    public BigInteger getP() {
        Asn1Integer p = getFieldAs(P, Asn1Integer.class);
        return p.getValue();
    }

    public void setG(BigInteger g) {
        setFieldAsBigInteger(G, g);
    }

    public BigInteger getG() {
        Asn1Integer g = getFieldAs(G, Asn1Integer.class);
        return g.getValue();
    }

    public void setQ(BigInteger q) {
        setFieldAsBigInteger(Q, q);
    }

    public BigInteger getQ() {
        Asn1Integer q = getFieldAs(Q, Asn1Integer.class);
        return q.getValue();
    }
}
