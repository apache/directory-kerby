package org.haox.kerb.spec.type.x509;

import org.haox.asn1.type.*;

/**
 AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm               OBJECT IDENTIFIER,
     parameters              ANY DEFINED BY algorithm OPTIONAL
 }
 */
public class AlgorithmIdentifier extends Asn1SequenceType {
    private static int ALGORITHM = 0;
    private static int PARAMETERS = 1;

    static Asn1FieldInfo[] tags = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ALGORITHM, -1, Asn1ObjectIdentifier.class),
            new Asn1FieldInfo(PARAMETERS, -1, Asn1Any.class)
    };

    public AlgorithmIdentifier(Asn1FieldInfo[] fieldInfos) {
        super(fieldInfos);
    }
}
