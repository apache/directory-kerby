package org.haox.kerb.spec.x509;

import org.apache.haox.asn1.type.*;

/**
 AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm               OBJECT IDENTIFIER,
     parameters              ANY DEFINED BY algorithm OPTIONAL
 }
 */
public class AlgorithmIdentifier extends Asn1SequenceType {
    private static int ALGORITHM = 0;
    private static int PARAMETERS = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ALGORITHM, -1, Asn1ObjectIdentifier.class),
            new Asn1FieldInfo(PARAMETERS, -1, Asn1Any.class)
    };

    public AlgorithmIdentifier() {
        super(fieldInfos);
    }

    public Asn1ObjectIdentifier getAlgorithm() {
        return getFieldAs(ALGORITHM, Asn1ObjectIdentifier.class);
    }

    public void setAlgorithm(Asn1ObjectIdentifier algorithm) {
        setFieldAs(ALGORITHM, algorithm);
    }

    public Asn1Type getParameters() {
        return getFieldAsAny(PARAMETERS);
    }

    public void setParameters(Asn1Type parameters) {
        setFieldAsAny(PARAMETERS, parameters);
    }
}
