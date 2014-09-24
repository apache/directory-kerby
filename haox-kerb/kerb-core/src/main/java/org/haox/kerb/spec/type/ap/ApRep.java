package org.haox.kerb.spec.type.ap;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.KrbMessageType;

/**
 AP-REP          ::= [APPLICATION 15] SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (15),
 enc-part        [2] EncryptedData -- EncAPRepPart
 }
 */
public class ApRep extends KrbMessage {
    private static int ENC_PART = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PVNO, 0, Asn1Integer.class),
            new Asn1FieldInfo(MSG_TYPE, 1, Asn1Integer.class),
            new Asn1FieldInfo(ENC_PART, 2, EncryptedData.class)
    };

    public ApRep() {
        super(KrbMessageType.AP_REP, fieldInfos);
    }

    private EncAPRepPart encRepPart;

    public EncAPRepPart getEncRepPart() {
        return encRepPart;
    }

    public void setEncRepPart(EncAPRepPart encRepPart) {
        this.encRepPart = encRepPart;
    }

    public EncryptedData getEncryptedEncPart() {
        return getFieldAs(ENC_PART, EncryptedData.class);
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) {
        setFieldAs(ENC_PART, encryptedEncPart);
    }
}
