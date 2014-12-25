package org.haox.kerb.spec.pa.pkinit;

import org.haox.asn1.type.Asn1BitString;
import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.KerberosTime;
import org.haox.kerb.spec.KrbSequenceType;

/**
 KDCDHKeyInfo ::= SEQUENCE {
    subjectPublicKey        [0] BIT STRING,
    nonce                   [1] INTEGER (0..4294967295),
    dhKeyExpiration         [2] KerberosTime OPTIONAL,
 }
 */
public class KdcDHKeyInfo extends KrbSequenceType {
    private static int SUBJECT_PUBLICK_KEY = 0;
    private static int NONCE = 1;
    private static int DH_KEY_EXPIRATION = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(SUBJECT_PUBLICK_KEY, Asn1BitString.class),
            new Asn1FieldInfo(NONCE, Asn1Integer.class),
            new Asn1FieldInfo(DH_KEY_EXPIRATION, KerberosTime.class)
    };

    public KdcDHKeyInfo() {
        super(fieldInfos);
    }

    public byte[] getSubjectPublicKey() {
        return getFieldAsOctets(SUBJECT_PUBLICK_KEY);
    }

    public void setSubjectPublicKey(byte[] subjectPublicKey) {
        setFieldAsOctets(SUBJECT_PUBLICK_KEY, subjectPublicKey);
    }

    public int getNonce() {
        return getFieldAsInt(NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(NONCE, nonce);
    }
}
