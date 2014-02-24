package org.haox.kerb.base;

/**
 LastReq         ::=     SEQUENCE OF SEQUENCE {
 lr-type         [0] Int32,
 lr-value        [1] KerberosTime
 }
 */
public class LastReqEntry {
    private LastReqType lrType;
    private KerberosTime lrValue;

    public LastReqType getLrType() {
        return lrType;
    }

    public void setLrType(LastReqType lrType) {
        this.lrType = lrType;
    }

    public KerberosTime getLrValue() {
        return lrValue;
    }

    public void setLrValue(KerberosTime lrValue) {
        this.lrValue = lrValue;
    }
}
