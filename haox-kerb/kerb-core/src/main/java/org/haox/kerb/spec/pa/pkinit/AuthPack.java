package org.haox.kerb.spec.pa.pkinit;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.haox.kerb.spec.KrbSequenceType;
import org.haox.kerb.spec.x509.SubjectPublicKeyInfo;

/**
 AuthPack ::= SEQUENCE {
     pkAuthenticator         [0] PKAuthenticator,
     clientPublicValue       [1] SubjectPublicKeyInfo OPTIONAL,
     supportedCMSTypes       [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
     clientDHNonce           [3] DHNonce OPTIONAL
 }
 */
public class AuthPack extends KrbSequenceType {
    private static int PK_AUTHENTICATOR = 0;
    private static int CLIENT_PUBLIC_VALUE = 1;
    private static int SUPPORTED_CMS_TYPES = 2;
    private static int CLIENT_DH_NONCE = 3;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PK_AUTHENTICATOR, PkAuthenticator.class),
            new Asn1FieldInfo(CLIENT_PUBLIC_VALUE, SubjectPublicKeyInfo.class),
            new Asn1FieldInfo(SUPPORTED_CMS_TYPES, AlgorithmIdentifiers.class),
            new Asn1FieldInfo(CLIENT_DH_NONCE, DHNonce.class)
    };

    public AuthPack() {
        super(fieldInfos);
    }

    public PkAuthenticator getPkAuthenticator() {
        return getFieldAs(PK_AUTHENTICATOR, PkAuthenticator.class);
    }

    public void setPkAuthenticator(PkAuthenticator pkAuthenticator) {
        setFieldAs(PK_AUTHENTICATOR, pkAuthenticator);
    }

    public SubjectPublicKeyInfo getClientPublicValue() {
        return getFieldAs(CLIENT_PUBLIC_VALUE, SubjectPublicKeyInfo.class);
    }

    public void setClientPublicValue(SubjectPublicKeyInfo clientPublicValue) {
        setFieldAs(CLIENT_PUBLIC_VALUE, clientPublicValue);
    }

    public AlgorithmIdentifiers getsupportedCmsTypes() {
        return getFieldAs(CLIENT_DH_NONCE, AlgorithmIdentifiers.class);
    }

    public void setsupportedCmsTypes(AlgorithmIdentifiers supportedCMSTypes) {
        setFieldAs(CLIENT_DH_NONCE, supportedCMSTypes);
    }

    public DHNonce getClientDhNonce() {
        return getFieldAs(CLIENT_DH_NONCE, DHNonce.class);
    }

    public void setClientDhNonce(DHNonce dhNonce) {
        setFieldAs(CLIENT_DH_NONCE, dhNonce);
    }
}
