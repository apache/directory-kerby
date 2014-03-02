package org.haox.kerb.spec.type.common;

/**
 LastReq         ::=     SEQUENCE OF SEQUENCE {
 lr-type         [0] Int32,
 lr-value        [1] KrbTime
 }
 */
public class LastReqEntry {
    private LastReqType lrType;
    private KrbTime lrValue;

    public LastReqType getLrType() {
        return lrType;
    }

    public void setLrType(LastReqType lrType) {
        this.lrType = lrType;
    }

    public KrbTime getLrValue() {
        return lrValue;
    }

    public void setLrValue(KrbTime lrValue) {
        this.lrValue = lrValue;
    }
}
