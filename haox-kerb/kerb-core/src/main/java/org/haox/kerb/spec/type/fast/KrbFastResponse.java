package org.haox.kerb.spec.type.fast;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.type.KrbSequenceType;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.pa.PaData;

/**
 KrbFastResponse ::= SEQUENCE {
     padata         [0] SEQUENCE OF PA-DATA,
     -- padata typed holes.
     strengthen-key [1] EncryptionKey OPTIONAL,
     -- This, if present, strengthens the reply key for AS and
     -- TGS. MUST be present for TGS.
     -- MUST be absent in KRB-ERROR.
     finished       [2] KrbFastFinished OPTIONAL,
     -- Present in AS or TGS reply; absent otherwise.
     nonce          [3] UInt32,
     -- Nonce from the client request.
 }
 */
public class KrbFastResponse extends KrbSequenceType {
    private static int PADATA = 0;
    private static int STRENGTHEN_KEY = 1;
    private static int FINISHED = 2;
    private static int NONCE = 3;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PADATA, PaData.class),
            new Asn1FieldInfo(STRENGTHEN_KEY, EncryptionKey.class),
            new Asn1FieldInfo(FINISHED, KrbFastFinished.class),
            new Asn1FieldInfo(NONCE, Asn1Integer.class)
    };

    public KrbFastResponse() {
        super(fieldInfos);
    }

    public PaData getPaData() {
        return getFieldAs(PADATA, PaData.class);
    }

    public void setPaData(PaData paData) {
        setFieldAs(PADATA, paData);
    }

    public EncryptionKey getStrengthenKey() {
        return getFieldAs(STRENGTHEN_KEY, EncryptionKey.class);
    }

    public void setStrengthenKey(EncryptionKey strengthenKey) {
        setFieldAs(STRENGTHEN_KEY, strengthenKey);
    }

    public KrbFastFinished getFastFinished() {
        return getFieldAs(FINISHED, KrbFastFinished.class);
    }

    public void setFastFinished(KrbFastFinished fastFinished) {
        setFieldAs(FINISHED, fastFinished);
    }

    public int getNonce() {
        return getFieldAsInt(NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(NONCE, nonce);
    }
}
