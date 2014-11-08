package org.haox.kerb.spec.type.pa.pkinit;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 DHRepInfo ::= SEQUENCE {
    dhSignedData            [0] IMPLICIT OCTET STRING,
    serverDHNonce           [1] DHNonce OPTIONAL
 }
 */
public class DHRepInfo extends KrbSequenceType {
    private static int DH_SIGNED_DATA = 0;
    private static int SERVER_DH_NONCE = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(DH_SIGNED_DATA, Asn1OctetString.class, true),
            new Asn1FieldInfo(SERVER_DH_NONCE, DHNonce.class)
    };

    public DHRepInfo() {
        super(fieldInfos);
    }

    public byte[] getDHSignedData() {
        return getFieldAsOctets(DH_SIGNED_DATA);
    }

    public void setDHSignedData(byte[] dhSignedData) {
        setFieldAsOctets(DH_SIGNED_DATA, dhSignedData);
    }

    public DHNonce getServerDhNonce() {
        return getFieldAs(SERVER_DH_NONCE, DHNonce.class);
    }

    public void setServerDhNonce(DHNonce dhNonce) {
        setFieldAs(SERVER_DH_NONCE, dhNonce);
    }
}
