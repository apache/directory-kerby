package org.apache.kerberos.kerb.spec.fast;

import org.apache.haox.asn1.type.Asn1Choice;
import org.apache.haox.asn1.type.Asn1FieldInfo;

/**
 PA-FX-FAST-REQUEST ::= CHOICE {
    armored-data [0] KrbFastArmoredReq,
 }
 */
public class PaFxFastRequest extends Asn1Choice {
    private static int ARMORED_DATA = 0;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ARMORED_DATA, KrbFastArmoredReq.class)
    };

    public PaFxFastRequest() {
        super(fieldInfos);
    }

    public KrbFastArmoredReq getFastArmoredReq() {
        return getFieldAs(ARMORED_DATA, KrbFastArmoredReq.class);
    }

    public void setFastArmoredReq(KrbFastArmoredReq fastArmoredReq) {
        setFieldAs(ARMORED_DATA, fastArmoredReq);
    }
}
