package org.haox.kerb.spec.fast;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.kerb.spec.KrbSequenceType;
import org.haox.kerb.spec.common.EncryptedData;

/**
 KrbFastArmoredRep ::= SEQUENCE {
    enc-fast-rep      [0] EncryptedData, -- KrbFastResponse --
    -- The encryption key is the armor key in the request, and
    -- the key usage number is KEY_USAGE_FAST_REP.
 }
 */
public class KrbFastArmoredRep extends KrbSequenceType {
    private static int ENC_FAST_REP = 0;

    //private
    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ENC_FAST_REP, EncryptedData.class)
    };

    public KrbFastArmoredRep() {
        super(fieldInfos);
    }

    public EncryptedData getEncFastRep() {
        return getFieldAs(ENC_FAST_REP, EncryptedData.class);
    }

    public void setEncFastRep(EncryptedData encFastRep) {
        setFieldAs(ENC_FAST_REP, encFastRep);
    }
}
