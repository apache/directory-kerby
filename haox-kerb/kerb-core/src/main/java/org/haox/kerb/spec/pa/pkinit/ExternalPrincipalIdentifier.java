package org.haox.kerb.spec.pa.pkinit;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.KrbSequenceType;

/**
 ExternalPrincipalIdentifier ::= SEQUENCE {
     subjectName             [0] IMPLICIT OCTET STRING OPTIONAL,
     issuerAndSerialNumber   [1] IMPLICIT OCTET STRING OPTIONAL,
     subjectKeyIdentifier    [2] IMPLICIT OCTET STRING OPTIONAL
 }
 */
public class ExternalPrincipalIdentifier extends KrbSequenceType {
    private static int SUBJECT_NAME = 0;
    private static int ISSUER_AND_SERIAL_NUMBER = 1;
    private static int SUBJECT_KEY_IDENTIFIER = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(SUBJECT_NAME, Asn1OctetString.class, true),
            new Asn1FieldInfo(ISSUER_AND_SERIAL_NUMBER, Asn1OctetString.class, true),
            new Asn1FieldInfo(SUBJECT_KEY_IDENTIFIER, Asn1OctetString.class, true)
    };

    public ExternalPrincipalIdentifier() {
        super(fieldInfos);
    }

    public byte[] getSubjectName() {
        return getFieldAsOctets(SUBJECT_NAME);
    }

    public void setSubjectName(byte[] subjectName) {
        setFieldAsOctets(SUBJECT_NAME, subjectName);
    }

    public byte[] getIssuerSerialNumber() {
        return getFieldAsOctets(ISSUER_AND_SERIAL_NUMBER);
    }

    public void setIssuerSerialNumber(byte[] issuerSerialNumber) {
        setFieldAsOctets(ISSUER_AND_SERIAL_NUMBER, issuerSerialNumber);
    }

    public byte[] getSubjectKeyIdentifier() {
        return getFieldAsOctets(SUBJECT_KEY_IDENTIFIER);
    }

    public void setSubjectKeyIdentifier(byte[] subjectKeyIdentifier) {
        setFieldAsOctets(SUBJECT_KEY_IDENTIFIER, subjectKeyIdentifier);
    }
}
