package org.apache.kerberos.kerb.spec.common;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1Integer;
import org.apache.kerberos.kerb.spec.KerberosTime;
import org.apache.kerberos.kerb.spec.KrbSequenceType;

/**
 LastReq         ::=     SEQUENCE OF SEQUENCE {
 lr-type         [0] Int32,
 lr-value        [1] KerberosTime
 }
 */
public class LastReqEntry extends KrbSequenceType {
    private static int LR_TYPE = 0;
    private static int LR_VALUE = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(LR_TYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(LR_VALUE, 1, KerberosTime.class)
    };

    public LastReqEntry() {
        super(fieldInfos);
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
