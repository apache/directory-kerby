package org.haox.kerb.spec.type.common;

import org.haox.asn1.Asn1Tag;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 LastReq         ::=     SEQUENCE OF SEQUENCE {
 lr-type         [0] Int32,
 lr-value        [1] KerberosTime
 }
 */
public class LastReqEntry extends KrbSequenceType {
    private static int LR_TYPE = 0;
    private static int LR_VALUE = 1;

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(LR_TYPE, 0, Asn1Integer.class),
            new Asn1Tag(LR_VALUE, 1, KerberosTime.class)
    };

    public LastReqEntry() {
        super(tags);
    }

    public LastReqType getLrType() {
        Integer value = getFieldAsInteger(LR_TYPE);
        return LastReqType.fromValue(value);
    }

    public void setLrType(LastReqType lrType) {
        setFieldAsInt(LR_TYPE, lrType.getValue());
    }

    public KerberosTime getLrValue() {
        return getFieldAs(LR_VALUE, KerberosTime.class);
    }

    public void setLrValue(KerberosTime lrValue) {
        setFieldAs(LR_VALUE, lrValue);
    }
}
