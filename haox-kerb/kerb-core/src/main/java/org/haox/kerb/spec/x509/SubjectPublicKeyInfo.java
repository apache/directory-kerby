package org.haox.kerb.spec.x509;

import org.apache.haox.asn1.type.Asn1BitString;
import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1SequenceType;

/**
 SubjectPublicKeyInfo  ::=  SEQUENCE  {
     algorithm            AlgorithmIdentifier,
     subjectPublicKey     BIT STRING
 }
 */
public class SubjectPublicKeyInfo extends Asn1SequenceType {
    private static int ALGORITHM = 0;
    private static int SUBJECT_PUBLIC_KEY = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ALGORITHM, -1, AlgorithmIdentifier.class),
            new Asn1FieldInfo(SUBJECT_PUBLIC_KEY, -1, Asn1BitString.class)
    };

    public SubjectPublicKeyInfo() {
        super(fieldInfos);
    }

    public AlgorithmIdentifier getAlgorithm() {
        return getFieldAs(ALGORITHM, AlgorithmIdentifier.class);
    }

    public void setAlgorithm(AlgorithmIdentifier algorithm) {
        setFieldAs(ALGORITHM, algorithm);
    }

    public byte[] getSubjectPubKey() {
        return getFieldAsOctets(SUBJECT_PUBLIC_KEY);
    }

    public void setSubjectPubKey(byte[] subjectPubKey) {
        setFieldAs(SUBJECT_PUBLIC_KEY, new Asn1BitString(subjectPubKey));
    }
}
