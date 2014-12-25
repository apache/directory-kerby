package org.haox.kerb.spec.fast;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.haox.kerb.spec.KrbSequenceType;
import org.haox.kerb.spec.common.EncryptedData;
import org.haox.kerb.spec.pa.PaData;

/**
 KrbFastReq ::= SEQUENCE {
     fast-options [0] FastOptions,
     -- Additional options.
     padata       [1] SEQUENCE OF PA-DATA,
     -- padata typed holes.
     req-body     [2] KDC-REQ-BODY,
     -- Contains the KDC request body as defined in Section
     -- 5.4.1 of [RFC4120].
     -- This req-body field is preferred over the outer field
     -- in the KDC request.
 }
 */
public class KrbFastReq extends KrbSequenceType {
    private static int FAST_OPTIONS = 0;
    private static int PADATA = 1;
    private static int REQ_BODY = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(FAST_OPTIONS, KrbFastArmor.class),
            new Asn1FieldInfo(PADATA, PaData.class),
            new Asn1FieldInfo(REQ_BODY, EncryptedData.class),
    };

    public KrbFastReq() {
        super(fieldInfos);
    }

    public KrbFastArmor getArmor() {
        return getFieldAs(FAST_OPTIONS, KrbFastArmor.class);
    }

    public void setArmor(KrbFastArmor armor) {
        setFieldAs(FAST_OPTIONS, armor);
    }

    public PaData getPaData() {
        return getFieldAs(PADATA, PaData.class);
    }

    public void setPaData(PaData paData) {
        setFieldAs(PADATA, paData);
    }

    public EncryptedData getEncFastReq() {
        return getFieldAs(REQ_BODY, EncryptedData.class);
    }

    public void setEncFastReq(EncryptedData encFastReq) {
        setFieldAs(REQ_BODY, encFastReq);
    }
}
