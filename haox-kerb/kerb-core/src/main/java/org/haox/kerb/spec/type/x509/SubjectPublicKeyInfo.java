package org.haox.kerb.spec.type.x509;

import org.haox.asn1.type.Asn1BitString;
import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1SequenceType;

/**
 SubjectPublicKeyInfo  ::=  SEQUENCE  {
     algorithm            AlgorithmIdentifier,
     subjectPublicKey     BIT STRING
 }
 */
public class SubjectPublicKeyInfo extends Asn1SequenceType {
    private static int ALGORITHM = 0;
    private static int SUBJECT_PUBLIC_KEY = 1;

    static Asn1FieldInfo[] tags = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ALGORITHM, -1, AlgorithmIdentifier.class),
            new Asn1FieldInfo(SUBJECT_PUBLIC_KEY, -1, Asn1BitString.class)
    };

    public SubjectPublicKeyInfo(Asn1FieldInfo[] fieldInfos) {
        super(fieldInfos);
    }
}
