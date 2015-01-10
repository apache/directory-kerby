package org.apache.kerberos.kerb.spec.pa.pkinit;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1OctetString;
import org.apache.kerberos.kerb.spec.KrbSequenceType;

/**
 PA-PK-AS-REQ ::= SEQUENCE {
     signedAuthPack          [0] IMPLICIT OCTET STRING,
     trustedCertifiers       [1] SEQUENCE OF ExternalPrincipalIdentifier OPTIONAL,
     kdcPkId                 [2] IMPLICIT OCTET STRING OPTIONAL
 }
 */
public class PaPkAsReq extends KrbSequenceType {
    private static int SIGNED_AUTH_PACK = 0;
    private static int TRUSTED_CERTIFIERS = 1;
    private static int KDC_PKID = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(SIGNED_AUTH_PACK, Asn1OctetString.class, true),
            new Asn1FieldInfo(TRUSTED_CERTIFIERS, TrustedCertifiers.class),
            new Asn1FieldInfo(KDC_PKID, Asn1OctetString.class, true)
    };

    public PaPkAsReq() {
        super(fieldInfos);
    }

    public byte[] getSignedAuthPack() {
        return getFieldAsOctets(SIGNED_AUTH_PACK);
    }

    public void setSignedAuthPack(byte[] signedAuthPack) {
        setFieldAsOctets(SIGNED_AUTH_PACK, signedAuthPack);
    }

    public TrustedCertifiers getTrustedCertifiers() {
        return getFieldAs(TRUSTED_CERTIFIERS, TrustedCertifiers.class);
    }

    public void setTrustedCertifiers(TrustedCertifiers trustedCertifiers) {
        setFieldAs(TRUSTED_CERTIFIERS, trustedCertifiers);
    }

    public byte[] getKdcPkId() {
        return getFieldAsOctets(KDC_PKID);
    }

    public void setKdcPkId(byte[] kdcPkId) {
        setFieldAsOctets(KDC_PKID, kdcPkId);
    }
}
