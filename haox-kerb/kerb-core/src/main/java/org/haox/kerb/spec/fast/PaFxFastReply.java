package org.haox.kerb.spec.fast;

import org.haox.asn1.type.Asn1Choice;
import org.haox.asn1.type.Asn1FieldInfo;

/**
 PA-FX-FAST-REPLY ::= CHOICE {
    armored-data [0] KrbFastArmoredRep,
 }
 */
public class PaFxFastReply extends Asn1Choice {
    private static int ARMORED_DATA = 0;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ARMORED_DATA, KrbFastArmoredRep.class)
    };

    public PaFxFastReply() {
        super(fieldInfos);
    }

    public KrbFastArmoredRep getFastArmoredRep() {
        return getFieldAs(ARMORED_DATA, KrbFastArmoredRep.class);
    }

    public void setFastArmoredRep(KrbFastArmoredRep fastArmoredRep) {
        setFieldAs(ARMORED_DATA, fastArmoredRep);
    }
}
